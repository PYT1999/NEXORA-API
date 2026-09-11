// NEXORA 33.0.0 API — Cloudflare Worker + D1
// D1 binding: env.DB

const PBKDF2_ITERATIONS = 100000;
const SESSION_DAYS = 30;
const MAX_BODY_BYTES = 300_000;
const COOKIE_NAME = "nx_session";
const MAX_CHARACTERS = 3;

const ALLOWED_ORIGINS = new Set([
  "https://nexorasystems.ch",
  "https://www.nexorasystems.ch",
  "http://localhost:8787",
  "http://127.0.0.1:8787"
]);

export default {
  async fetch(request, env) {
    const origin = request.headers.get("Origin") || "";
    const cors = corsHeaders(origin);
    const url = new URL(request.url);

    if (request.method === "OPTIONS") {
      if (origin && !ALLOWED_ORIGINS.has(origin))
        return json({ error: "Origin nicht erlaubt." }, 403, cors);

      return new Response(null, {
        status: 204,
        headers: cors
      });
    }

    if (
      url.pathname.startsWith("/api/") &&
      origin &&
      !ALLOWED_ORIGINS.has(origin)
    ) {
      return json(
        { error: "Origin nicht erlaubt." },
        403,
        cors
      );
    }

    try {

      if (url.pathname === "/health") {
        return json(
          {
            ok: true,
            service: "nexora-api",
            version: "33.0.0"
          },
          200,
          cors
        );
      }

      // ==================================================
      // REGISTER
      // ==================================================

      if (
        url.pathname === "/api/register" &&
        request.method === "POST"
      ) {
        const body = await readJson(request);

        const email = normalizeEmail(body.email);
        const password = String(body.password || "");

        if (!isValidEmail(email)) {
          return json(
            { error: "Ungültige E-Mail-Adresse." },
            400,
            cors
          );
        }

        if (!isValidPassword(password)) {
          return json(
            {
              error:
                "Passwort benötigt mindestens 8 Zeichen, Groß- und Kleinbuchstaben sowie mindestens eine Zahl."
            },
            400,
            cors
          );
        }

        if (
          await env.DB
            .prepare("SELECT id FROM users WHERE email=?")
            .bind(email)
            .first()
        ) {
          return json(
            {
              error:
                "Für diese E-Mail existiert bereits ein Account."
            },
            409,
            cors
          );
        }

        const id = crypto.randomUUID();

        const salt = crypto.getRandomValues(
          new Uint8Array(16)
        );

        const hash = await passwordHash(
          password,
          salt,
          PBKDF2_ITERATIONS
        );

        const now = Date.now();

        try {
          await env.DB
            .prepare(`
              INSERT INTO users
              (
                id,
                email,
                password_hash,
                password_salt,
                password_iterations,
                created_at,
                updated_at
              )
              VALUES (?,?,?,?,?,?,?)
            `)
            .bind(
              id,
              email,
              toBase64(hash),
              toBase64(salt),
              PBKDF2_ITERATIONS,
              now,
              now
            )
            .run();

        } catch (e) {

          if (
            String(e)
              .toLowerCase()
              .includes("unique")
          ) {
            return json(
              {
                error:
                  "Für diese E-Mail existiert bereits ein Account."
              },
              409,
              cors
            );
          }

          throw e;
        }

        const session =
          await createSession(
            env.DB,
            id
          );

        return json(
          {
            ok: true,
            email
          },
          201,
          cors,
          {
            "Set-Cookie":
              sessionCookie(
                session.token
              )
          }
        );
      }

      // ==================================================
      // LOGIN
      // ==================================================

      if (
        url.pathname === "/api/login" &&
        request.method === "POST"
      ) {
        const body =
          await readJson(request);

        const email =
          normalizeEmail(
            body.email
          );

        const password =
          String(
            body.password || ""
          );

        if (
          !isValidEmail(email) ||
          !password
        ) {
          return json(
            {
              error:
                "E-Mail oder Passwort ist falsch."
            },
            401,
            cors
          );
        }

        const user =
          await env.DB
            .prepare(`
              SELECT
                id,
                email,
                password_hash,
                password_salt,
                password_iterations
              FROM users
              WHERE email=?
            `)
            .bind(email)
            .first();

        if (!user) {
          return json(
            {
              error:
                "E-Mail oder Passwort ist falsch."
            },
            401,
            cors
          );
        }

        const candidate =
          await passwordHash(
            password,
            fromBase64(
              user.password_salt
            ),
            Number(
              user.password_iterations
            ) ||
              PBKDF2_ITERATIONS
          );

        if (
          !constantTimeEqual(
            candidate,
            fromBase64(
              user.password_hash
            )
          )
        ) {
          return json(
            {
              error:
                "E-Mail oder Passwort ist falsch."
            },
            401,
            cors
          );
        }

        const session =
          await createSession(
            env.DB,
            user.id
          );

        return json(
          {
            ok: true,
            email: user.email
          },
          200,
          cors,
          {
            "Set-Cookie":
              sessionCookie(
                session.token
              )
          }
        );
      }

      // ==================================================
      // LOGOUT
      // ==================================================

      if (
        url.pathname === "/api/logout" &&
        request.method === "POST"
      ) {
        const raw =
          sessionToken(
            request
          );

        if (raw) {
          await env.DB
            .prepare(`
              DELETE FROM sessions
              WHERE token_hash=?
            `)
            .bind(
              await sha256Base64(
                raw
              )
            )
            .run();
        }

        return json(
          {
            ok: true
          },
          200,
          cors,
          {
            "Set-Cookie":
              clearSessionCookie()
          }
        );
      }

      // ==================================================
      // ACCOUNT
      // ==================================================

      if (
        url.pathname === "/api/me" &&
        request.method === "GET"
      ) {
        const auth =
          await requireUser(
            request,
            env.DB
          );

        if (!auth) {
          return json(
            {
              error:
                "Nicht angemeldet."
            },
            401,
            cors
          );
        }

        return json(
          {
            ok: true,
            id: auth.id,
            email: auth.email
          },
          200,
          cors
        );
      }

      const auth =
        await requireUser(
          request,
          env.DB
        );

      if (
        url.pathname.startsWith(
          "/api/characters"
        ) &&
        !auth
      ) {
        return json(
          {
            error:
              "Nicht angemeldet."
          },
          401,
          cors
        );
      }

      // ==================================================
      // CHARACTER LIST
      // ==================================================

      if (
        url.pathname === "/api/characters" &&
        request.method === "GET"
      ) {
        await migrateLegacyCharacter(
          env.DB,
          auth.id
        );

        const rows =
          await env.DB
            .prepare(`
              SELECT
                id,
                name,
                character_class AS cls,
                server_name AS server,
                character_level AS level,
                slot,
                created_at,
                updated_at
              FROM characters
              WHERE user_id=?
              ORDER BY slot
            `)
            .bind(auth.id)
            .all();

        return json(
          {
            ok: true,
            characters:
              rows.results || []
          },
          200,
          cors
        );
      }

      // ==================================================
      // CREATE CHARACTER
      // ==================================================

      if (
        url.pathname === "/api/characters" &&
        request.method === "POST"
      ) {
        await migrateLegacyCharacter(
          env.DB,
          auth.id
        );

        const countRow =
          await env.DB
            .prepare(`
              SELECT COUNT(*) AS n
              FROM characters
              WHERE user_id=?
            `)
            .bind(auth.id)
            .first();

        if (
          Number(
            countRow?.n || 0
          ) >= MAX_CHARACTERS
        ) {
          return json(
            {
              error:
                "Du hast bereits alle 3 Charakter-Slots belegt."
            },
            409,
            cors
          );
        }

        const body =
          await readJson(
            request
          );

        const name =
          cleanCharacterName(
            body.name
          );

        const cls =
          cleanClass(
            body.cls
          );

        const server =
          cleanText(
            body.server,
            40
          ) ||
          "Ashen Realm";

        const requestedSlot =
          clampInt(
            body.slot,
            1,
            MAX_CHARACTERS,
            0
          );

        if (
          name.length < 3 ||
          name.length > 18
        ) {
          return json(
            {
              error:
                "Charaktername muss 3–18 Zeichen lang sein."
            },
            400,
            cors
          );
        }

        if (
          !/^[\p{L}\p{N} _-]+$/u.test(
            name
          )
        ) {
          return json(
            {
              error:
                "Charaktername enthält ungültige Zeichen."
            },
            400,
            cors
          );
        }

        if (
          await env.DB
            .prepare(`
              SELECT id
              FROM characters
              WHERE name=? COLLATE NOCASE
            `)
            .bind(name)
            .first()
        ) {
          return json(
            {
              error:
                "Dieser Charaktername ist bereits vergeben."
            },
            409,
            cors
          );
        }

        const used =
          await env.DB
            .prepare(`
              SELECT slot
              FROM characters
              WHERE user_id=?
              ORDER BY slot
            `)
            .bind(auth.id)
            .all();

        const usedSlots =
          new Set(
            (used.results || [])
              .map(
                r =>
                  Number(r.slot)
              )
          );

        let slot =
          requestedSlot &&
          !usedSlots.has(
            requestedSlot
          )
            ? requestedSlot
            : 0;

        if (!slot) {
          for (
            let i = 1;
            i <= MAX_CHARACTERS;
            i++
          ) {
            if (
              !usedSlots.has(i)
            ) {
              slot = i;
              break;
            }
          }
        }

        if (!slot) {
          return json(
            {
              error:
                "Kein freier Charakter-Slot."
            },
            409,
            cors
          );
        }

        const id =
          crypto.randomUUID();

        const now =
          Date.now();

        try {

          await env.DB
            .prepare(`
              INSERT INTO characters
              (
                id,
                user_id,
                name,
                character_class,
                server_name,
                character_level,
                game_save,
                slot,
                created_at,
                updated_at
              )
              VALUES (?,?,?,?,?,?,?,?,?,?)
            `)
            .bind(
              id,
              auth.id,
              name,
              cls,
              server,
              1,
              "{}",
              slot,
              now,
              now
            )
            .run();

        } catch (e) {

          const m =
            String(e)
              .toLowerCase();

          if (
            m.includes("unique") &&
            m.includes("name")
          ) {
            return json(
              {
                error:
                  "Dieser Charaktername ist bereits vergeben."
              },
              409,
              cors
            );
          }

          if (
            m.includes("unique")
          ) {
            return json(
              {
                error:
                  "Dieser Charakter-Slot ist bereits belegt."
              },
              409,
              cors
            );
          }

          throw e;
        }

        const character = {
          id,
          name,
          cls,
          server,
          level: 1,
          slot,
          created_at: now,
          updated_at: now
        };

        return json(
          {
            ok: true,
            character
          },
          201,
          cors
        );
      }

      // ==================================================
      // DELETE CHARACTER
      // ==================================================

      const charMatch =
        url.pathname.match(
          /^\/api\/characters\/([^/]+)$/
        );

      if (
        charMatch &&
        request.method === "DELETE"
      ) {
        const id =
          decodeURIComponent(
            charMatch[1]
          );

        const row =
          await env.DB
            .prepare(`
              SELECT id
              FROM characters
              WHERE id=?
              AND user_id=?
            `)
            .bind(
              id,
              auth.id
            )
            .first();

        if (!row) {
          return json(
            {
              error:
                "Charakter nicht gefunden."
            },
            404,
            cors
          );
        }

        await env.DB
          .prepare(`
            DELETE FROM characters
            WHERE id=?
            AND user_id=?
          `)
          .bind(
            id,
            auth.id
          )
          .run();

        return json(
          {
            ok: true
          },
          200,
          cors
        );
      }

      // ==================================================
      // CHARACTER SAVE
      // ==================================================

      const saveMatch =
        url.pathname.match(
          /^\/api\/characters\/([^/]+)\/save$/
        );

      if (
        saveMatch &&
        request.method === "GET"
      ) {
        const id =
          decodeURIComponent(
            saveMatch[1]
          );

        const row =
          await env.DB
            .prepare(`
              SELECT
                id,
                name,
                character_class AS cls,
                server_name AS server,
                character_level AS level,
                slot,
                game_save,
                updated_at
              FROM characters
              WHERE id=?
              AND user_id=?
            `)
            .bind(
              id,
              auth.id
            )
            .first();

        if (!row) {
          return json(
            {
              error:
                "Charakter nicht gefunden."
            },
            404,
            cors
          );
        }

        return json(
          {
            ok: true,

            character: {
              id: row.id,
              name: row.name,
              cls: row.cls,
              server: row.server,
              level: row.level,
              slot: row.slot
            },

            gameSave:
              safeParse(
                row.game_save,
                {}
              ),

            updatedAt:
              row.updated_at
          },
          200,
          cors
        );
      }

      if (
        saveMatch &&
        request.method === "PUT"
      ) {
        const id =
          decodeURIComponent(
            saveMatch[1]
          );

        const body =
          await readJson(
            request
          );

        const exists =
          await env.DB
            .prepare(`
              SELECT id
              FROM characters
              WHERE id=?
              AND user_id=?
            `)
            .bind(
              id,
              auth.id
            )
            .first();

        if (!exists) {
          return json(
            {
              error:
                "Charakter nicht gefunden."
            },
            404,
            cors
          );
        }

        const gameSave =
          body.gameSave &&
          typeof body.gameSave ===
            "object"
            ? body.gameSave
            : {};

        const txt =
          JSON.stringify(
            gameSave
          );

        if (
          txt.length >
          200_000
        ) {
          return json(
            {
              error:
                "Spielstand ist zu groß."
            },
            413,
            cors
          );
        }

        const level =
          clampInt(
            body.level ??
              gameSave.level,
            1,
            999,
            1
          );

        const now =
          Date.now();

        await env.DB
          .prepare(`
            UPDATE characters
            SET
              character_level=?,
              game_save=?,
              updated_at=?
            WHERE id=?
            AND user_id=?
          `)
          .bind(
            level,
            txt,
            now,
            id,
            auth.id
          )
          .run();

        return json(
          {
            ok: true,
            updatedAt: now,
            level
          },
          200,
          cors
        );
      }

      // ==================================================
      // NEXORA 32 COMPATIBILITY
      // ==================================================

      if (
        url.pathname === "/api/save" &&
        request.method === "GET"
      ) {
        await migrateLegacyCharacter(
          env.DB,
          auth.id
        );

        const row =
          await env.DB
            .prepare(`
              SELECT
                id,
                name,
                character_class,
                server_name,
                character_level,
                game_save,
                updated_at
              FROM characters
              WHERE user_id=?
              ORDER BY slot
              LIMIT 1
            `)
            .bind(auth.id)
            .first();

        return json(
          {
            ok: true,

            player: row
              ? {
                  characterId:
                    row.id,

                  server:
                    row.server_name,

                  character: {
                    name:
                      row.name,

                    cls:
                      row.character_class,

                    level:
                      row.character_level
                  },

                  gameSave:
                    safeParse(
                      row.game_save,
                      {}
                    ),

                  updatedAt:
                    row.updated_at
                }
              : null
          },
          200,
          cors
        );
      }

      if (
        url.pathname === "/api/save" &&
        request.method === "PUT"
      ) {
        await migrateLegacyCharacter(
          env.DB,
          auth.id
        );

        const row =
          await env.DB
            .prepare(`
              SELECT id
              FROM characters
              WHERE user_id=?
              ORDER BY slot
              LIMIT 1
            `)
            .bind(auth.id)
            .first();

        if (!row) {
          return json(
            {
              error:
                "Erstelle zuerst einen Charakter."
            },
            409,
            cors
          );
        }

        const body =
          await readJson(
            request
          );

        const gameSave =
          body.gameSave &&
          typeof body.gameSave ===
            "object"
            ? body.gameSave
            : {};

        const txt =
          JSON.stringify(
            gameSave
          );

        if (
          txt.length >
          200_000
        ) {
          return json(
            {
              error:
                "Spielstand ist zu groß."
            },
            413,
            cors
          );
        }

        const level =
          clampInt(
            body.character?.level ??
              gameSave.level,
            1,
            999,
            1
          );

        const now =
          Date.now();

        await env.DB
          .prepare(`
            UPDATE characters
            SET
              character_level=?,
              game_save=?,
              updated_at=?
            WHERE id=?
            AND user_id=?
          `)
          .bind(
            level,
            txt,
            now,
            row.id,
            auth.id
          )
          .run();

        return json(
          {
            ok: true,
            updatedAt: now
          },
          200,
          cors
        );
      }

      return json(
        {
          error:
            "Route nicht gefunden."
        },
        404,
        cors
      );

    } catch (err) {

      console.error(err);

      const status =
        err &&
        err.status
          ? err.status
          : 500;

      return json(
        {
          error:
            status === 500
              ? "Interner Serverfehler."
              : (
                  err.message ||
                  "Fehler."
                )
        },
        status,
        corsHeaders(
          request.headers.get(
            "Origin"
          ) || ""
        )
      );
    }
  }
};


// ======================================================
// OLD SAVE → CHARACTER SLOT 1
// ======================================================

async function migrateLegacyCharacter(
  db,
  userId
) {

  const has =
    await db
      .prepare(`
        SELECT id
        FROM characters
        WHERE user_id=?
        LIMIT 1
      `)
      .bind(userId)
      .first();

  if (has) {
    return;
  }

  const legacy =
    await db
      .prepare(`
        SELECT
          server_name,
          character_name,
          character_class,
          character_level,
          game_save,
          updated_at
        FROM player_data
        WHERE user_id=?
      `)
      .bind(userId)
      .first();

  if (!legacy) {
    return;
  }

  let name =
    cleanCharacterName(
      legacy.character_name ||
      "Ashborn"
    ) ||
    "Ashborn";

  if (
    await db
      .prepare(`
        SELECT id
        FROM characters
        WHERE name=? COLLATE NOCASE
      `)
      .bind(name)
      .first()
  ) {

    name =
      (
        name.slice(0, 12) +
        "-" +
        userId.slice(-5)
      ).slice(
        0,
        18
      );

    let n = 1;
    let base = name;

    while (
      await db
        .prepare(`
          SELECT id
          FROM characters
          WHERE name=? COLLATE NOCASE
        `)
        .bind(name)
        .first()
    ) {

      name =
        (
          base.slice(
            0,
            15
          ) +
          n
        ).slice(
          0,
          18
        );

      n++;
    }
  }

  const now =
    Date.now();

  await db
    .prepare(`
      INSERT INTO characters
      (
        id,
        user_id,
        name,
        character_class,
        server_name,
        character_level,
        game_save,
        slot,
        created_at,
        updated_at
      )
      VALUES (?,?,?,?,?,?,?,?,?,?)
    `)
    .bind(
      crypto.randomUUID(),
      userId,
      name,
      cleanClass(
        legacy.character_class
      ),
      cleanText(
        legacy.server_name,
        40
      ) ||
        "Ashen Realm",
      clampInt(
        legacy.character_level,
        1,
        999,
        1
      ),
      legacy.game_save ||
        "{}",
      1,
      Number(
        legacy.updated_at
      ) ||
        now,
      now
    )
    .run();
}


// ======================================================
// HELPERS
// ======================================================

function corsHeaders(origin) {

  const h = {
    "Cache-Control":
      "no-store",

    "Access-Control-Allow-Headers":
      "Content-Type",

    "Access-Control-Allow-Methods":
      "GET, POST, PUT, DELETE, OPTIONS",

    "Access-Control-Allow-Credentials":
      "true",

    "Vary":
      "Origin"
  };

  if (
    ALLOWED_ORIGINS.has(
      origin
    )
  ) {
    h[
      "Access-Control-Allow-Origin"
    ] = origin;
  }

  return h;
}


function json(
  data,
  status = 200,
  headers = {},
  extra = {}
) {

  return new Response(
    JSON.stringify(data),
    {
      status,

      headers: {
        ...headers,
        ...extra,

        "Content-Type":
          "application/json; charset=utf-8"
      }
    }
  );
}


async function readJson(
  request
) {

  const len =
    Number(
      request.headers.get(
        "Content-Length"
      ) || 0
    );

  if (
    len >
    MAX_BODY_BYTES
  ) {
    throw Object.assign(
      new Error(
        "Anfrage ist zu groß."
      ),
      {
        status: 413
      }
    );
  }

  const text =
    await request.text();

  if (
    text.length >
    MAX_BODY_BYTES
  ) {
    throw Object.assign(
      new Error(
        "Anfrage ist zu groß."
      ),
      {
        status: 413
      }
    );
  }

  try {
    return text
      ? JSON.parse(text)
      : {};
  } catch {
    throw Object.assign(
      new Error(
        "Ungültige JSON-Daten."
      ),
      {
        status: 400
      }
    );
  }
}


function normalizeEmail(v) {
  return String(
    v || ""
  )
    .trim()
    .toLowerCase();
}


function isValidEmail(v) {
  return (
    v.length <= 254 &&
    /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v)
  );
}


function isValidPassword(p) {
  return (
    p.length >= 8 &&
    p.length <= 128 &&
    /[A-Z]/.test(p) &&
    /[a-z]/.test(p) &&
    /\d/.test(p)
  );
}


function cleanText(
  v,
  max
) {
  return String(
    v || ""
  )
    .trim()
    .replace(
      /\s+/g,
      " "
    )
    .slice(
      0,
      max
    );
}


function cleanCharacterName(v) {
  return cleanText(
    v,
    18
  );
}


function cleanClass(v) {
  const x =
    String(
      v || ""
    )
      .toUpperCase();

  return [
    "WARRIOR",
    "RANGER",
    "MAGE"
  ].includes(x)
    ? x
    : "WARRIOR";
}


function clampInt(
  v,
  min,
  max,
  fallback
) {
  const n =
    Number.parseInt(
      v,
      10
    );

  return Number.isFinite(n)
    ? Math.max(
        min,
        Math.min(
          max,
          n
        )
      )
    : fallback;
}


function safeParse(
  v,
  fallback
) {
  try {
    return JSON.parse(v);
  } catch {
    return fallback;
  }
}


function sessionCookie(token) {

  return (
    `${COOKIE_NAME}=${token}; ` +
    `Path=/; ` +
    `HttpOnly; ` +
    `Secure; ` +
    `SameSite=Strict; ` +
    `Max-Age=${SESSION_DAYS * 86400}`
  );
}


function clearSessionCookie() {

  return (
    `${COOKIE_NAME}=; ` +
    `Path=/; ` +
    `HttpOnly; ` +
    `Secure; ` +
    `SameSite=Strict; ` +
    `Max-Age=0`
  );
}


function sessionToken(
  request
) {

  const cookie =
    request.headers.get(
      "Cookie"
    ) || "";

  for (
    const part of
    cookie.split(";")
  ) {

    const [
      k,
      ...rest
    ] =
      part
        .trim()
        .split("=");

    if (
      k ===
      COOKIE_NAME
    ) {
      return rest.join("=");
    }
  }

  return "";
}


async function requireUser(
  request,
  db
) {

  const raw =
    sessionToken(
      request
    );

  if (!raw) {
    return null;
  }

  const hash =
    await sha256Base64(
      raw
    );

  const now =
    Date.now();

  const row =
    await db
      .prepare(`
        SELECT
          u.id,
          u.email
        FROM sessions s
        JOIN users u
          ON u.id =
             s.user_id
        WHERE
          s.token_hash=?
        AND
          s.expires_at>?
      `)
      .bind(
        hash,
        now
      )
      .first();

  return row
    ? {
        id: row.id,
        email: row.email
      }
    : null;
}


async function createSession(
  db,
  userId
) {

  const bytes =
    crypto.getRandomValues(
      new Uint8Array(32)
    );

  const token =
    toBase64Url(
      bytes
    );

  const tokenHash =
    await sha256Base64(
      token
    );

  const now =
    Date.now();

  const expiresAt =
    now +
    SESSION_DAYS *
      86400000;

  await db
    .prepare(`
      INSERT INTO sessions
      (
        token_hash,
        user_id,
        created_at,
        expires_at
      )
      VALUES (?,?,?,?)
    `)
    .bind(
      tokenHash,
      userId,
      now,
      expiresAt
    )
    .run();

  await db
    .prepare(`
      DELETE FROM sessions
      WHERE expires_at<=?
    `)
    .bind(now)
    .run();

  return {
    token,
    expiresAt
  };
}


async function passwordHash(
  password,
  salt,
  iterations
) {

  const material =
    await crypto.subtle.importKey(
      "raw",

      new TextEncoder()
        .encode(
          password
        ),

      {
        name: "PBKDF2"
      },

      false,

      [
        "deriveBits"
      ]
    );

  const bits =
    await crypto.subtle.deriveBits(
      {
        name: "PBKDF2",
        salt,
        iterations,
        hash: "SHA-256"
      },

      material,

      256
    );

  return new Uint8Array(
    bits
  );
}


async function sha256Base64(
  text
) {

  return toBase64(
    new Uint8Array(
      await crypto.subtle.digest(
        "SHA-256",

        new TextEncoder()
          .encode(
            text
          )
      )
    )
  );
}


function constantTimeEqual(
  a,
  b
) {

  if (
    a.length !==
    b.length
  ) {
    return false;
  }

  let diff = 0;

  for (
    let i = 0;
    i < a.length;
    i++
  ) {
    diff |=
      a[i] ^
      b[i];
  }

  return diff === 0;
}


function toBase64(bytes) {

  let x = "";

  for (
    const b of bytes
  ) {
    x +=
      String.fromCharCode(
        b
      );
  }

  return btoa(x);
}


function fromBase64(s) {

  const raw =
    atob(s);

  const out =
    new Uint8Array(
      raw.length
    );

  for (
    let i = 0;
    i < raw.length;
    i++
  ) {
    out[i] =
      raw.charCodeAt(i);
  }

  return out;
}


function toBase64Url(bytes) {

  return toBase64(
    bytes
  )
    .replace(
      /\+/g,
      "-"
    )
    .replace(
      /\//g,
      "_"
    )
    .replace(
      /=+$/g,
      ""
    );
}
