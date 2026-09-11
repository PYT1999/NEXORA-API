import { DurableObject } from "cloudflare:workers";

// NEXORA 34.0.0 API — Cloudflare Worker + D1 + Realtime Realms
// D1 binding: env.DB

const PBKDF2_ITERATIONS = 100000;
const SESSION_DAYS = 30;
const MAX_BODY_BYTES = 300_000;
const COOKIE_NAME = "nx_session";
const MAX_CHARACTERS = 3;

const RESET_CODE_TTL_MS = 10 * 60 * 1000;
const RESET_REQUEST_COOLDOWN_MS = 60 * 1000;
const RESET_MAX_ATTEMPTS = 5;

const ALLOWED_ORIGINS = new Set([
  "https://nexorasystems.ch",
  "https://www.nexorasystems.ch",
  "http://localhost:8787",
  "http://127.0.0.1:8787"
]);

export default {
  async fetch(request, env) {

    const origin =
      request.headers.get("Origin") || "";

    const cors =
      corsHeaders(origin);

    const url =
      new URL(request.url);


    if (request.method === "OPTIONS") {

      if (
        origin &&
        !ALLOWED_ORIGINS.has(origin)
      ) {
        return json(
          {
            error:
              "Origin nicht erlaubt."
          },
          403,
          cors
        );
      }

      return new Response(
        null,
        {
          status: 204,
          headers: cors
        }
      );
    }


    if (
      url.pathname.startsWith("/api/") &&
      origin &&
      !ALLOWED_ORIGINS.has(origin)
    ) {

      return json(
        {
          error:
            "Origin nicht erlaubt."
        },
        403,
        cors
      );
    }


    try {

      // ==================================================
      // HEALTH
      // ==================================================

      if (
if (url.pathname === "/health") {
  return json({
    ok: true,
    service: "nexora-api",
    version: "34.1.0",
    multiplayer: true,
    passwordReset: true,
    passwordResetConfigured: !!(
      env.RESEND_API_KEY &&
      env.RESET_FROM_EMAIL &&
      env.PASSWORD_RESET_SECRET
    )
  }, 200, cors);
}


      // ==================================================
      // REGISTER
      // ==================================================

      if (
        url.pathname === "/api/register" &&
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
          !isValidEmail(email)
        ) {

          return json(
            {
              error:
                "Ungültige E-Mail-Adresse."
            },
            400,
            cors
          );
        }


        if (
          !isValidPassword(password)
        ) {

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
            .prepare(
              "SELECT id FROM users WHERE email=?"
            )
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


        const id =
          crypto.randomUUID();


        const salt =
          crypto.getRandomValues(
            new Uint8Array(16)
          );


        const hash =
          await passwordHash(
            password,
            salt,
            PBKDF2_ITERATIONS
          );


        const now =
          Date.now();


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

        }
        catch (e) {

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
// PASSWORD RESET
// ==================================================

if (
  url.pathname === "/api/password-reset/request" &&
  request.method === "POST"
) {
  const body = await readJson(request);
  const email = normalizeEmail(body.email);

  if (!isValidEmail(email)) {
    return json(
      {
        error: "Bitte eine gültige E-Mail-Adresse eingeben."
      },
      400,
      cors
    );
  }

  if (
    !env.RESEND_API_KEY ||
    !env.RESET_FROM_EMAIL ||
    !env.PASSWORD_RESET_SECRET
  ) {
    return json(
      {
        error:
          "Passwort-Wiederherstellung ist noch nicht vollständig eingerichtet."
      },
      503,
      cors
    );
  }

  await ensurePasswordResetTable(env.DB);

  const user = await env.DB
    .prepare(`
      SELECT id,email
      FROM users
      WHERE email=?
    `)
    .bind(email)
    .first();

  /*
   Absichtlich gleiche Antwort,
   auch wenn die Mail nicht existiert.
  */
  const publicResult = {
    ok: true,
    message:
      "Wenn für diese E-Mail ein NEXORA-Account existiert, wurde ein Reset-Code gesendet."
  };

  if (!user) {
    return json(publicResult, 200, cors);
  }

  const now = Date.now();

  const recent = await env.DB
    .prepare(`
      SELECT created_at
      FROM password_reset_codes
      WHERE user_id=?
      ORDER BY created_at DESC
      LIMIT 1
    `)
    .bind(user.id)
    .first();

  /*
   Maximal 1 Reset-Code pro Minute.
  */
  if (
    recent &&
    now - Number(recent.created_at || 0) <
      RESET_REQUEST_COOLDOWN_MS
  ) {
    return json(publicResult, 200, cors);
  }

  const code = randomResetCode();

  const codeHash = await resetCodeHash(
    env.PASSWORD_RESET_SECRET,
    email,
    code
  );

  const resetId = crypto.randomUUID();
  const expiresAt = now + RESET_CODE_TTL_MS;

  /*
   Alle vorherigen Codes ungültig machen.
  */
  await env.DB
    .prepare(`
      UPDATE password_reset_codes
      SET used_at=?
      WHERE user_id=?
      AND used_at IS NULL
    `)
    .bind(now, user.id)
    .run();

  await env.DB
    .prepare(`
      INSERT INTO password_reset_codes
      (
        id,
        user_id,
        code_hash,
        created_at,
        expires_at,
        attempts,
        used_at
      )
      VALUES (?,?,?,?,?,?,NULL)
    `)
    .bind(
      resetId,
      user.id,
      codeHash,
      now,
      expiresAt,
      0
    )
    .run();

  const sent = await sendPasswordResetEmail(
    env,
    user.email,
    code
  );

  if (!sent) {
    await env.DB
      .prepare(`
        UPDATE password_reset_codes
        SET used_at=?
        WHERE id=?
      `)
      .bind(
        Date.now(),
        resetId
      )
      .run();

    console.error(
      "NEXORA password reset email could not be sent for",
      user.id
    );
  }

  return json(
    publicResult,
    200,
    cors
  );
}


if (
  url.pathname === "/api/password-reset/confirm" &&
  request.method === "POST"
) {
  const body = await readJson(request);

  const email = normalizeEmail(
    body.email
  );

  const code = String(
    body.code || ""
  ).replace(/\s+/g, "");

  const newPassword = String(
    body.newPassword || ""
  );

  const confirmPassword = String(
    body.confirmPassword || ""
  );

  if (
    !isValidEmail(email) ||
    !/^\d{6}$/.test(code)
  ) {
    return json(
      {
        error:
          "Reset-Code ist ungültig oder abgelaufen."
      },
      400,
      cors
    );
  }

  if (
    !isValidPassword(newPassword)
  ) {
    return json(
      {
        error:
          "Neues Passwort benötigt mindestens 8 Zeichen, Groß- und Kleinbuchstaben sowie mindestens eine Zahl."
      },
      400,
      cors
    );
  }

  if (
    newPassword !== confirmPassword
  ) {
    return json(
      {
        error:
          "Die beiden neuen Passwörter stimmen nicht überein."
      },
      400,
      cors
    );
  }

  if (!env.PASSWORD_RESET_SECRET) {
    return json(
      {
        error:
          "Passwort-Wiederherstellung ist noch nicht vollständig eingerichtet."
      },
      503,
      cors
    );
  }

  await ensurePasswordResetTable(
    env.DB
  );

  const user = await env.DB
    .prepare(`
      SELECT id,email
      FROM users
      WHERE email=?
    `)
    .bind(email)
    .first();

  if (!user) {
    return json(
      {
        error:
          "Reset-Code ist ungültig oder abgelaufen."
      },
      400,
      cors
    );
  }

  const now = Date.now();

  const row = await env.DB
    .prepare(`
      SELECT
        id,
        code_hash,
        attempts,
        expires_at
      FROM password_reset_codes
      WHERE user_id=?
      AND used_at IS NULL
      AND expires_at>?
      ORDER BY created_at DESC
      LIMIT 1
    `)
    .bind(
      user.id,
      now
    )
    .first();

  if (
    !row ||
    Number(row.attempts || 0) >=
      RESET_MAX_ATTEMPTS
  ) {
    return json(
      {
        error:
          "Reset-Code ist ungültig oder abgelaufen."
      },
      400,
      cors
    );
  }

  const candidateHash =
    await resetCodeHash(
      env.PASSWORD_RESET_SECRET,
      email,
      code
    );

  if (
    !constantTimeStringEqual(
      candidateHash,
      String(row.code_hash || "")
    )
  ) {
    const nextAttempts =
      Number(row.attempts || 0) + 1;

    if (
      nextAttempts >=
      RESET_MAX_ATTEMPTS
    ) {
      await env.DB
        .prepare(`
          UPDATE password_reset_codes
          SET attempts=?,
              used_at=?
          WHERE id=?
        `)
        .bind(
          nextAttempts,
          now,
          row.id
        )
        .run();

    } else {

      await env.DB
        .prepare(`
          UPDATE password_reset_codes
          SET attempts=?
          WHERE id=?
        `)
        .bind(
          nextAttempts,
          row.id
        )
        .run();
    }

    return json(
      {
        error:
          "Reset-Code ist ungültig oder abgelaufen."
      },
      400,
      cors
    );
  }


  const salt =
    crypto.getRandomValues(
      new Uint8Array(16)
    );


  const hash =
    await passwordHash(
      newPassword,
      salt,
      PBKDF2_ITERATIONS
    );


  /*
   Nur Passwort-Daten werden geändert.
   Charaktere und Saves bleiben unangetastet.
  */
  await env.DB
    .prepare(`
      UPDATE users
      SET
        password_hash=?,
        password_salt=?,
        password_iterations=?,
        updated_at=?
      WHERE id=?
    `)
    .bind(
      toBase64(hash),
      toBase64(salt),
      PBKDF2_ITERATIONS,
      now,
      user.id
    )
    .run();


  /*
   Alle alten Sessions beenden.
  */
  await env.DB
    .prepare(`
      DELETE FROM sessions
      WHERE user_id=?
    `)
    .bind(
      user.id
    )
    .run();


  /*
   Reset-Code endgültig verbrauchen.
  */
  await env.DB
    .prepare(`
      UPDATE password_reset_codes
      SET used_at=?
      WHERE user_id=?
      AND used_at IS NULL
    `)
    .bind(
      now,
      user.id
    )
    .run();


  /*
   Direkt neue Session erzeugen.
  */
  const session =
    await createSession(
      env.DB,
      user.id
    );


  return json(
    {
      ok: true,
      email: user.email,
      message:
        "Passwort wurde zurückgesetzt."
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
      // REALTIME MULTIPLAYER
      // ==================================================

      if (
        url.pathname === "/api/realtime" &&
        request.method === "GET"
      ) {

        if (
          (
            request.headers.get(
              "Upgrade"
            ) || ""
          )
          .toLowerCase() !==
          "websocket"
        ) {

          return json(
            {
              error:
                "WebSocket Upgrade erforderlich."
            },
            426,
            cors
          );
        }


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


        const characterId =
          cleanText(
            url.searchParams.get(
              "characterId"
            ),
            80
          );


        if (!characterId) {

          return json(
            {
              error:
                "characterId fehlt."
            },
            400,
            cors
          );
        }


        /*
         WICHTIG:

         Realm, Name, Klasse und Level
         werden NICHT vom Browser vertraut.

         Sie kommen direkt aus D1.
        */

        const character =
          await env.DB
            .prepare(`
              SELECT
                id,
                name,
                character_class AS cls,
                server_name AS server,
                character_level AS level
              FROM characters
              WHERE id=?
              AND user_id=?
            `)
            .bind(
              characterId,
              auth.id
            )
            .first();


        if (!character) {

          return json(
            {
              error:
                "Charakter nicht gefunden."
            },
            404,
            cors
          );
        }


        /*
         Jeder Realm erhält automatisch
         sein eigenes Durable Object.

         Beispiel:

         realm:Ashen Realm
         realm:Blackwater
         realm:Old Ruins
        */

        const roomId =
          env.REALMS
            .idFromName(
              "realm:" +
              character.server
            );


        const room =
          env.REALMS
            .get(
              roomId
            );


        /*
         Die Identität wurde bereits
         serverseitig über Session + D1
         geprüft.

         Erst danach wird sie intern
         an RealmRoom weitergegeben.
        */

        const headers =
          new Headers(
            request.headers
          );


        headers.set(
          "x-nexora-user-id",
          auth.id
        );


        headers.set(
          "x-nexora-character-id",
          character.id
        );


        headers.set(
          "x-nexora-character-name",
          character.name
        );


        headers.set(
          "x-nexora-character-class",
          character.cls
        );


        headers.set(
          "x-nexora-character-level",
          String(
            character.level || 1
          )
        );


        headers.set(
          "x-nexora-realm",
          character.server
        );


        return room.fetch(
          new Request(
            request,
            {
              headers
            }
          )
        );
      }


      // ==================================================
      // CURRENT ACCOUNT
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
async function ensurePasswordResetTable(db) {

  await db
    .prepare(`
      CREATE TABLE IF NOT EXISTS password_reset_codes
      (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        code_hash TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL,
        attempts INTEGER NOT NULL DEFAULT 0,
        used_at INTEGER,

        FOREIGN KEY (user_id)
        REFERENCES users(id)
        ON DELETE CASCADE
      )
    `)
    .run();


  await db
    .prepare(`
      CREATE INDEX IF NOT EXISTS idx_password_reset_user
      ON password_reset_codes
      (
        user_id,
        created_at DESC
      )
    `)
    .run();
}


function randomResetCode() {

  const values =
    new Uint32Array(1);

  crypto.getRandomValues(
    values
  );

  return String(
    values[0] % 1000000
  ).padStart(
    6,
    "0"
  );
}


async function resetCodeHash(
  secret,
  email,
  code
) {

  return sha256Base64(
    String(secret) +
    "|" +
    normalizeEmail(email) +
    "|" +
    String(code)
  );
}


function constantTimeStringEqual(
  a,
  b
) {

  a = String(a);
  b = String(b);

  if (
    a.length !== b.length
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
      a.charCodeAt(i) ^
      b.charCodeAt(i);
  }

  return diff === 0;
}


async function sendPasswordResetEmail(
  env,
  to,
  code
) {

  try {

    const response =
      await fetch(
        "https://api.resend.com/emails",
        {
          method: "POST",

          headers: {
            "Authorization":
              "Bearer " +
              env.RESEND_API_KEY,

            "Content-Type":
              "application/json"
          },

          body:
            JSON.stringify({
              from:
                env.RESET_FROM_EMAIL,

              to: [
                to
              ],

              subject:
                "NEXORA – Passwort zurücksetzen",

              text:
                `Dein NEXORA Reset-Code lautet: ${code}\n\n` +
                `Der Code ist 10 Minuten gültig.\n\n` +
                `Falls du das nicht angefordert hast, ignoriere diese E-Mail.`,

              html: `
<div style="
  font-family:Arial,sans-serif;
  background:#0b0d10;
  color:#eee;
  padding:28px
">
  <h2 style="
    letter-spacing:.12em
  ">
    NEXORA
  </h2>

  <p>
    Du hast das Zurücksetzen deines Passworts angefordert.
  </p>

  <p style="
    font-size:30px;
    font-weight:800;
    letter-spacing:.25em
  ">
    ${code}
  </p>

  <p>
    Der Code ist <b>10 Minuten</b> gültig.
  </p>

  <p style="
    color:#9aa0aa
  ">
    Falls du das nicht angefordert hast,
    ignoriere diese E-Mail.
  </p>
</div>
`
            })
        }
      );


    if (!response.ok) {

      console.error(
        "Resend error",
        response.status,
        await response.text()
      );

      return false;
    }


    return true;

  }
  catch (error) {

    console.error(
      "Resend request failed",
      error
    );

    return false;
  }
}
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
            .bind(
              auth.id
            )
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
            .bind(
              auth.id
            )
            .first();


        if (
          Number(
            countRow?.n || 0
          ) >=
          MAX_CHARACTERS
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
            .bind(
              name
            )
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
            .bind(
              auth.id
            )
            .all();


        const usedSlots =
          new Set(
            (
              used.results ||
              []
            )
            .map(
              r =>
                Number(
                  r.slot
                )
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

        }
        catch (e) {

          const message =
            String(e)
              .toLowerCase();


          if (
            message.includes("unique") &&
            message.includes("name")
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
            message.includes("unique")
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
      // CHARACTER SAVE GET
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


      // ==================================================
      // CHARACTER SAVE PUT
      // ==================================================

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
            .bind(
              auth.id
            )
            .first();


        return json(
          {
            ok: true,

            player:
              row
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
            .bind(
              auth.id
            )
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

    }
    catch (err) {

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
// LEGACY PLAYER → CHARACTER SLOT 1
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
      .bind(
        userId
      )
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
      .bind(
        userId
      )
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
        name.slice(
          0,
          12
        ) +
        "-" +
        userId.slice(-5)
      )
      .slice(
        0,
        18
      );


    let number = 1;

    const base =
      name;


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
          number
        )
        .slice(
          0,
          18
        );


      number++;
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

function corsHeaders(
  origin
) {

  const headers = {

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

    headers[
      "Access-Control-Allow-Origin"
    ] =
      origin;
  }


  return headers;
}


function json(
  data,
  status = 200,
  headers = {},
  extra = {}
) {

  return new Response(
    JSON.stringify(
      data
    ),
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
      ) ||
      0
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

  }
  catch {

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


function normalizeEmail(
  value
) {

  return String(
    value || ""
  )
  .trim()
  .toLowerCase();
}


function isValidEmail(
  value
) {

  return (
    value.length <= 254 &&
    /^[^\s@]+@[^\s@]+\.[^\s@]+$/
      .test(value)
  );
}


function isValidPassword(
  password
) {

  return (
    password.length >= 8 &&
    password.length <= 128 &&
    /[A-Z]/.test(password) &&
    /[a-z]/.test(password) &&
    /\d/.test(password)
  );
}


function cleanText(
  value,
  max
) {

  return String(
    value || ""
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


function cleanCharacterName(
  value
) {

  return cleanText(
    value,
    18
  );
}


function cleanClass(
  value
) {

  const characterClass =
    String(
      value || ""
    )
    .toUpperCase();


  return [
    "WARRIOR",
    "RANGER",
    "MAGE"
  ]
  .includes(
    characterClass
  )
    ? characterClass
    : "WARRIOR";
}


function clampInt(
  value,
  min,
  max,
  fallback
) {

  const number =
    Number.parseInt(
      value,
      10
    );


  return Number.isFinite(
    number
  )
    ? Math.max(
        min,
        Math.min(
          max,
          number
        )
      )
    : fallback;
}


function safeParse(
  value,
  fallback
) {

  try {

    return JSON.parse(
      value
    );

  }
  catch {

    return fallback;
  }
}


function sessionCookie(
  token
) {

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
    ) ||
    "";


  for (
    const part of
    cookie.split(";")
  ) {

    const [
      key,
      ...rest
    ] =
      part
        .trim()
        .split("=");


    if (
      key ===
      COOKIE_NAME
    ) {

      return rest.join(
        "="
      );
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
    .bind(
      now
    )
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


function toBase64(
  bytes
) {

  let text = "";


  for (
    const byte of
    bytes
  ) {

    text +=
      String.fromCharCode(
        byte
      );
  }


  return btoa(
    text
  );
}


function fromBase64(
  text
) {

  const raw =
    atob(
      text
    );


  const output =
    new Uint8Array(
      raw.length
    );


  for (
    let i = 0;
    i < raw.length;
    i++
  ) {

    output[i] =
      raw.charCodeAt(
        i
      );
  }


  return output;
}


function toBase64Url(
  bytes
) {

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


// ======================================================
// REALM DURABLE OBJECT
// ======================================================

export class RealmRoom extends DurableObject {

  constructor(
    ctx,
    env
  ) {

    super(
      ctx,
      env
    );


    this.ctx =
      ctx;


    this.env =
      env;
  }


  async fetch(
    request
  ) {

    if (
      (
        request.headers.get(
          "Upgrade"
        ) || ""
      )
      .toLowerCase() !==
      "websocket"
    ) {

      return new Response(
        "WebSocket required",
        {
          status: 426
        }
      );
    }


    /*
     Diese Werte kommen NICHT
     direkt vom Browser.

     Der normale Worker hat vorher
     Session + D1 validiert.
    */

    const userId =
      request.headers.get(
        "x-nexora-user-id"
      ) ||
      "";


    const characterId =
      request.headers.get(
        "x-nexora-character-id"
      ) ||
      "";


    const name =
      cleanText(
        request.headers.get(
          "x-nexora-character-name"
        ),
        18
      ) ||
      "Ashborn";


    const cls =
      cleanClass(
        request.headers.get(
          "x-nexora-character-class"
        )
      );


    const level =
      clampInt(
        request.headers.get(
          "x-nexora-character-level"
        ),
        1,
        999,
        1
      );


    const realm =
      cleanText(
        request.headers.get(
          "x-nexora-realm"
        ),
        40
      ) ||
      "Ashen Realm";


    if (
      !userId ||
      !characterId
    ) {

      return new Response(
        "Missing verified identity",
        {
          status: 401
        }
      );
    }


    /*
     Derselbe Charakter darf
     nicht gleichzeitig zweimal
     online sein.
    */

    for (
      const socket of
      this.ctx.getWebSockets()
    ) {

      const old =
        safeSocketAttachment(
          socket
        );


      if (
        old?.characterId ===
        characterId
      ) {

        try {

          socket.close(
            4001,
            "Character connected elsewhere"
          );

        }
        catch {}
      }
    }


    /*
     WebSocket-Paar erzeugen.
    */

    const pair =
      new WebSocketPair();


    const [
      client,
      server
    ] =
      Object.values(
        pair
      );


    /*
     Hibernation API.

     Dadurch kann Cloudflare
     den Realm schlafen lassen,
     ohne Spieler zu trennen.
    */

    this.ctx
      .acceptWebSocket(
        server,
        [
          "realm-player"
        ]
      );


    const player = {

      userId,

      characterId,

      name,

      cls,

      level,

      realm,

      x: 1050,

      y: 1450,

      dir: "down",

      moving: false,

      attacking: false,

      /*
       Beim ersten State darf der
       Charakter an seine gespeicherte
       Position springen.

       Erst danach greift die
       Anti-Teleport-Prüfung.
      */

      hasState: false,

      lastMessageAt: 0,

      lastStateAt:
        Date.now()
    };


    /*
     Wichtig für Hibernation:
     Spielerdaten hängen direkt
     am WebSocket.
    */

    server.serializeAttachment(
      player
    );


    /*
     Neuer Spieler bekommt zuerst
     alle Spieler, die bereits
     im Realm sind.
    */

    const snapshot = [];


    for (
      const socket of
      this.ctx.getWebSockets(
        "realm-player"
      )
    ) {

      if (
        socket ===
        server
      ) {
        continue;
      }


      const other =
        safeSocketAttachment(
          socket
        );


      if (
        other?.characterId
      ) {

        snapshot.push(
          publicRealmPlayer(
            other
          )
        );
      }
    }


    try {

      server.send(
        JSON.stringify({
          t: "snapshot",
          realm,
          players: snapshot
        })
      );

    }
    catch {}


    /*
     Allen anderen mitteilen:
     Neuer Spieler ist da.
    */

    this.broadcast(
      {
        t: "join",
        player:
          publicRealmPlayer(
            player
          )
      },
      server
    );


    this.broadcastPresence();


    return new Response(
      null,
      {
        status: 101,
        webSocket: client
      }
    );
  }


  // ====================================================
  // PLAYER STATE
  // ====================================================

  async webSocketMessage(
    ws,
    message
  ) {

    if (
      typeof message !==
        "string" ||
      message.length > 4096
    ) {

      return;
    }


    let data;


    try {

      data =
        JSON.parse(
          message
        );

    }
    catch {

      return;
    }


    if (
      !data ||
      data.t !==
        "state"
    ) {

      return;
    }


    const player =
      safeSocketAttachment(
        ws
      );


    if (
      !player?.characterId
    ) {

      return;
    }


    const now =
      Date.now();


    /*
     Maximal ungefähr 30
     State-Nachrichten pro Sekunde.
    */

    if (
      player.lastMessageAt &&
      now -
        player.lastMessageAt <
        33
    ) {

      return;
    }


    const x =
      Number(
        data.x
      );


    const y =
      Number(
        data.y
      );


    if (
      !Number.isFinite(x) ||
      !Number.isFinite(y)
    ) {

      return;
    }


    /*
     Weltgrenzen aus deinem
     aktuellen NEXORA:

     7200 × 4800
    */

    const nextX =
      Math.max(
        20,
        Math.min(
          7180,
          x
        )
      );


    const nextY =
      Math.max(
        20,
        Math.min(
          4780,
          y
        )
      );


    /*
     Einfache serverseitige
     Anti-Teleport-Prüfung.

     Deine normale Laufgeschwindigkeit
     liegt deutlich darunter.

     Extra Spielraum ist für
     Lags + Dodge vorgesehen.
    */

    const elapsedMs =
      Math.max(
        1,
        now -
        (
          player.lastStateAt ||
          now
        )
      );


    const allowedDistance =
      90 +
      (
        elapsedMs /
        1000
      ) *
      950;


    const travelled =
      Math.hypot(
        nextX -
          player.x,
        nextY -
          player.y
      );


    /*
     Erster State darf die gespeicherte
     Position übernehmen.
    */

    if (
      player.hasState &&
      travelled >
        allowedDistance
    ) {

      try {

        ws.send(
          JSON.stringify({
            t: "correction",
            x: player.x,
            y: player.y
          })
        );

      }
      catch {}


      player.lastMessageAt =
        now;


      ws.serializeAttachment(
        player
      );


      return;
    }


    player.x =
      nextX;


    player.y =
      nextY;


    player.dir =
      [
        "up",
        "down",
        "left",
        "right"
      ]
      .includes(
        data.dir
      )
        ? data.dir
        : "down";


    player.moving =
      !!data.moving;


    player.attacking =
      !!data.attacking;


    player.hasState =
      true;


    player.lastMessageAt =
      now;


    player.lastStateAt =
      now;


    /*
     Neuen Zustand an
     alle anderen Spieler senden.
    */

    ws.serializeAttachment(
      player
    );


    this.broadcast(
      {
        t: "state",

        player:
          publicRealmPlayer(
            player
          )
      },
      ws
    );
  }


  // ====================================================
  // DISCONNECT
  // ====================================================

  async webSocketClose(
    ws
  ) {

    const player =
      safeSocketAttachment(
        ws
      );


    if (
      player?.characterId
    ) {

      this.broadcast(
        {
          t: "leave",
          id:
            player.characterId
        },
        ws
      );
    }


    this.broadcastPresence();
  }


  async webSocketError(
    ws
  ) {

    const player =
      safeSocketAttachment(
        ws
      );


    if (
      player?.characterId
    ) {

      this.broadcast(
        {
          t: "leave",
          id:
            player.characterId
        },
        ws
      );
    }


    try {

      ws.close(
        1011,
        "Realm socket error"
      );

    }
    catch {}


    this.broadcastPresence();
  }


  // ====================================================
  // BROADCAST
  // ====================================================

  broadcast(
    payload,
    except = null
  ) {

    const text =
      JSON.stringify(
        payload
      );


    for (
      const socket of
      this.ctx.getWebSockets(
        "realm-player"
      )
    ) {

      if (
        socket ===
        except
      ) {
        continue;
      }


      try {

        socket.send(
          text
        );

      }
      catch {}
    }
  }


  broadcastPresence() {

    let count = 0;


    for (
      const socket of
      this.ctx.getWebSockets(
        "realm-player"
      )
    ) {

      if (
        safeSocketAttachment(
          socket
        )
        ?.characterId
      ) {

        count++;
      }
    }


    this.broadcast(
      {
        t: "presence",
        count
      }
    );
  }
}


// ======================================================
// REALM HELPERS
// ======================================================

function safeSocketAttachment(
  ws
) {

  try {

    return (
      ws.deserializeAttachment() ||
      null
    );

  }
  catch {

    return null;
  }
}


function publicRealmPlayer(
  player
) {

  return {

    id:
      player.characterId,

    name:
      player.name,

    cls:
      player.cls,

    level:
      player.level,

    x:
      player.x,

    y:
      player.y,

    dir:
      player.dir,

    moving:
      !!player.moving,

    attacking:
      !!player.attacking
  };
}
