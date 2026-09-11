/**
 * Autenticación OAuth 2.0 con Passport.js (Sprint Miércoles).
 *
 * - Se usa en modo "stateless" (session: false): al volver del proveedor se emite nuestro propio JWT.
 * - Cada estrategia solo se registra si sus credenciales existen en .env; así el proyecto
 *   arranca aunque el equipo aún no haya creado las apps en Google o GitHub.
 * - Vinculación segura: una cuenta existente con el mismo correo solo se enlaza si el proveedor
 *   confirma que ese correo está verificado (evita secuestro de cuentas).
 */
const passport = require('passport');
const { Strategy: GoogleStrategy } = require('passport-google-oauth20');
const { Strategy: GitHubStrategy } = require('passport-github2');
const User = require('../models/User');
const { AppError } = require('../middlewares/errorHandler');
const { sanitizeString } = require('../middlewares/security');

const enabledProviders = { google: false, github: false };

const OAUTH_SCOPES = Object.freeze({
  google: ['openid', 'profile', 'email'],
  github: ['read:user', 'user:email'],
});

/** Limpia el nombre que entrega el proveedor para que cumpla las reglas del sistema. */
function nombreSeguro(nombreProveedor, email) {
  const limpio = sanitizeString(String(nombreProveedor || ''))
    .replace(/[^\p{L}' .-]/gu, ' ')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, 80);
  return limpio.length >= 2 ? limpio : String(email).split('@')[0].slice(0, 80);
}

async function resolveOAuthUser({ provider, providerId, email, emailVerificado, nombre }) {
  const existingByProvider = await User.findByProvider(provider, providerId);
  if (existingByProvider) return existingByProvider;

  if (!email) {
    throw new AppError('El proveedor no compartió un correo electrónico verificado.', 400);
  }

  const existingByEmail = await User.findByEmail(email);
  if (existingByEmail) {
    if (!emailVerificado) {
      throw new AppError('No se puede vincular la cuenta: el correo del proveedor no está verificado.', 403);
    }
    return User.linkProvider(existingByEmail.id, provider, providerId);
  }

  return User.createFromOAuth({ nombre: nombreSeguro(nombre, email), email, provider, providerId });
}

function configurePassport() {
  const baseUrl = (process.env.APP_BASE_URL || 'http://localhost:3000').replace(/\/+$/, '');

  if (process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET) {
    passport.use(
      new GoogleStrategy(
        {
          clientID: process.env.GOOGLE_CLIENT_ID,
          clientSecret: process.env.GOOGLE_CLIENT_SECRET,
          callbackURL: `${baseUrl}/api/auth/google/callback`,
        },
        async (accessToken, refreshToken, profile, done) => {
          try {
            const user = await resolveOAuthUser({
              provider: 'google',
              providerId: profile.id,
              email: profile.emails?.[0]?.value,
              emailVerificado: profile._json?.email_verified === true,
              nombre: profile.displayName,
            });
            done(null, user);
          } catch (err) {
            done(err);
          }
        }
      )
    );
    enabledProviders.google = true;
  }

  if (process.env.GITHUB_CLIENT_ID && process.env.GITHUB_CLIENT_SECRET) {
    passport.use(
      new GitHubStrategy(
        {
          clientID: process.env.GITHUB_CLIENT_ID,
          clientSecret: process.env.GITHUB_CLIENT_SECRET,
          callbackURL: `${baseUrl}/api/auth/github/callback`,
          scope: OAUTH_SCOPES.github,
          allRawEmails: true, // incluye el indicador "verified" de cada correo
        },
        async (accessToken, refreshToken, profile, done) => {
          try {
            const principal =
              profile.emails?.find((e) => e.primary && e.verified) || profile.emails?.find((e) => e.verified);
            const user = await resolveOAuthUser({
              provider: 'github',
              providerId: profile.id,
              email: principal?.value,
              emailVerificado: Boolean(principal?.verified),
              nombre: profile.displayName || profile.username,
            });
            done(null, user);
          } catch (err) {
            done(err);
          }
        }
      )
    );
    enabledProviders.github = true;
  }

  return passport;
}

module.exports = { configurePassport, enabledProviders, OAUTH_SCOPES, passport };
