/**
 * Módulo de validaciones de formularios (estructura y datos) — Sprint Martes.
 *
 * Conserva la API del material del Lunes (window.Validators con emailRegex, passwordRegex,
 * sanitizeInput, validateUserForm y validateGastoForm) y agrega:
 *  - Las MISMAS expresiones regulares que usa el backend (src/middlewares/security.js).
 *  - Reglas por campo y utilidades para mostrar errores accesibles en el DOM.
 *
 * IMPORTANTE sobre XSS:
 *  - La defensa principal al pintar datos es element.textContent (nunca innerHTML).
 *  - sanitizeInput() convierte < > " ' en entidades HTML. Solo sirve si el texto se va a insertar
 *    como HTML. Si se aplica ANTES de textContent, el usuario verá "&lt;" o "O&#x27;Brien" en pantalla.
 *    Para textContent usa limpiarTexto().
 *  - La validación del cliente mejora la experiencia, pero NO es una barrera de seguridad:
 *    cualquiera puede saltarla con curl o DevTools. El backend vuelve a validar todo.
 */
(function () {
  'use strict';

  // --- Expresiones regulares (idénticas a las del servidor) ---------------------------
  const emailRegex = /^[a-z0-9._%+-]{1,64}@[a-z0-9-]+(\.[a-z0-9-]+)*\.[a-z]{2,24}$/i;
  // 8 a 72 caracteres, con minúscula, mayúscula, número y cualquier símbolo.
  const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9\s]).{8,72}$/;
  const nombreRegex = /^[\p{L}][\p{L}' .-]{1,79}$/u;
  // Texto libre sin < > { } ` (no puede transportar etiquetas ni plantillas).
  const textoSeguroRegex = /^[\p{L}\p{N} .,;:()#/&%$'"!?¿¡+_-]{3,100}$/u;
  const montoRegex = /^\d{1,6}(\.\d{1,2})?$/;
  const fechaRegex = /^\d{4}-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])$/;
  const codigoRegex = /^\d{6}$/;
  const patronCodigo = /<\s*\/?\s*[a-z!?][^>]*>|(?:java|vb)script\s*:|\bon[a-z]+\s*=|[<>{}`]/i;

  const MONTO_MAXIMO_USD = 100000;
  const CATEGORIAS = ['transporte', 'alimentacion', 'hospedaje', 'software', 'equipos', 'otros'];

  // --- Utilidades de texto -----------------------------------------------------------

  /** Escapa HTML. Úsala solo si vas a construir HTML como string (en este proyecto no se hace). */
  function sanitizeInput(inputString) {
    return String(inputString)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#x27;')
      .replace(/\//g, '&#x2F;');
  }

  /** Limpieza para texto que irá a textContent o al servidor: normaliza Unicode y quita caracteres de control. */
  function limpiarTexto(valor) {
    return String(valor ?? '')
      .normalize('NFKC')
      .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, '')
      .trim();
  }

  /** Detecta etiquetas HTML, esquemas javascript:, manejadores on*= y caracteres de plantilla. */
  function contieneCodigo(valor) {
    return patronCodigo.test(String(valor ?? '').normalize('NFKC'));
  }

  /** Acepta "125,50" o "125.50" y devuelve "125.50". */
  function normalizarMonto(valor) {
    const limpio = limpiarTexto(valor).replace(/\s/g, '');
    return /^\d+,\d{1,2}$/.test(limpio) ? limpio.replace(',', '.') : limpio;
  }

  function fechaLocalIso(fecha) {
    const desfase = fecha.getTimezoneOffset() * 60000;
    return new Date(fecha.getTime() - desfase).toISOString().slice(0, 10);
  }

  const MENSAJE_CODIGO = 'No se permiten etiquetas HTML, scripts ni los caracteres < > { } `.';

  // --- Reglas por campo: devuelven '' si es válido o el mensaje de error --------------
  const reglas = {
    nombre(valor) {
      const v = limpiarTexto(valor);
      if (!v) return 'Escribe tu nombre.';
      if (contieneCodigo(v)) return MENSAJE_CODIGO;
      return nombreRegex.test(v) ? '' : 'Usa solo letras, espacios, apóstrofos o guiones (de 2 a 80).';
    },
    email(valor) {
      const v = limpiarTexto(valor);
      if (!v) return 'Escribe tu correo.';
      return emailRegex.test(v) && v.length <= 254 ? '' : 'Escribe un correo válido, por ejemplo nombre@empresa.com.';
    },
    passwordLogin(valor) {
      return String(valor ?? '').length ? '' : 'Escribe tu contraseña.';
    },
    password(valor) {
      const v = String(valor ?? '');
      if (!v) return 'Crea una contraseña.';
      if (new TextEncoder().encode(v).length > 72) return 'La contraseña es demasiado larga.';
      return passwordRegex.test(v) ? '' : 'Necesita de 8 a 72 caracteres con mayúscula, minúscula, número y símbolo.';
    },
    passwordConfirm(valor, formulario) {
      const original = formulario?.elements.namedItem('password')?.value ?? '';
      if (!valor) return 'Repite la contraseña.';
      return valor === original ? '' : 'Las contraseñas no coinciden.';
    },
    descripcion(valor) {
      const v = limpiarTexto(valor);
      if (!v) return 'Describe el gasto.';
      if (contieneCodigo(v)) return MENSAJE_CODIGO;
      return textoSeguroRegex.test(v) ? '' : 'Usa de 3 a 100 caracteres: letras, números y puntuación básica.';
    },
    categoria(valor) {
      return CATEGORIAS.includes(valor) ? '' : 'Selecciona una categoría.';
    },
    montoEnUSD(valor) {
      const v = normalizarMonto(valor);
      if (!v) return 'Escribe el monto en dólares.';
      if (!montoRegex.test(v)) return 'Usa solo números con máximo 2 decimales, por ejemplo 125.50.';
      const n = Number(v);
      if (n <= 0) return 'El monto debe ser mayor que cero.';
      return n <= MONTO_MAXIMO_USD ? '' : 'El monto máximo por gasto es US$ 100.000.';
    },
    fechaGasto(valor) {
      if (!fechaRegex.test(valor)) return 'Selecciona la fecha del gasto.';
      const hoy = new Date();
      const manana = fechaLocalIso(new Date(hoy.getTime() + 86400000));
      const haceUnAnio = fechaLocalIso(new Date(hoy.getTime() - 365 * 86400000));
      if (valor > manana) return 'La fecha no puede ser futura.';
      return valor >= haceUnAnio ? '' : 'Solo se aceptan gastos del último año.';
    },
    code(valor) {
      const v = limpiarTexto(valor);
      return codigoRegex.test(v) ? '' : 'El código tiene exactamente 6 dígitos.';
    },
    comentario(valor, decision) {
      const v = limpiarTexto(valor);
      if (!v) return decision === 'rechazado' ? 'Explica el motivo del rechazo.' : '';
      if (contieneCodigo(v)) return MENSAJE_CODIGO;
      return textoSeguroRegex.test(v) ? '' : 'Usa de 3 a 100 caracteres: letras, números y puntuación básica.';
    },
  };

  // --- API del material del Lunes (compatibilidad) ------------------------------------
  function validateUserForm(email, password) {
    if (!email || !password) return { isValid: false, message: 'Todos los campos son obligatorios.' };
    const errorEmail = reglas.email(email);
    if (errorEmail) return { isValid: false, message: errorEmail };
    const errorPassword = reglas.password(password);
    if (errorPassword) return { isValid: false, message: errorPassword };
    return { isValid: true, message: 'Validación de estructura exitosa.' };
  }

  function validateGastoForm(descripcion, monto) {
    const error = reglas.descripcion(descripcion) || reglas.montoEnUSD(monto);
    return error
      ? { isValid: false, message: error }
      : { isValid: true, message: 'Datos del gasto verificados correctamente.' };
  }

  // --- Utilidades de DOM (solo textContent y atributos) --------------------------------
  function elementoError(input) {
    return input.id ? document.getElementById(`${input.id}-error`) : null;
  }

  function mostrarError(input, mensaje) {
    const error = elementoError(input);
    input.setAttribute('aria-invalid', mensaje ? 'true' : 'false');
    if (!error) return;

    const descritoPor = new Set((input.getAttribute('aria-describedby') || '').split(/\s+/).filter(Boolean));
    descritoPor.add(error.id);
    input.setAttribute('aria-describedby', [...descritoPor].join(' '));
    error.textContent = mensaje || '';
  }

  function mostrarErrorGeneral(formulario, mensaje) {
    const contenedor = formulario.querySelector('[data-rol="error-general"]');
    if (contenedor) contenedor.textContent = mensaje || '';
  }

  function limpiarErrores(formulario) {
    for (const input of formulario.querySelectorAll('input, select, textarea')) mostrarError(input, '');
    mostrarErrorGeneral(formulario, '');
  }

  /** Valida todos los campos del mapa de reglas; enfoca el primero con error. */
  function validarFormulario(formulario, mapaReglas) {
    let primerInvalido = null;
    for (const [nombre, regla] of Object.entries(mapaReglas)) {
      const input = formulario.elements.namedItem(nombre);
      if (!input) continue;
      const mensaje = regla(input.value, formulario);
      mostrarError(input, mensaje);
      if (mensaje && !primerInvalido) primerInvalido = input;
    }
    if (primerInvalido) primerInvalido.focus();
    return !primerInvalido;
  }

  /** Valida al salir del campo y revalida mientras se corrige un error. */
  function activarValidacionEnVivo(formulario, mapaReglas) {
    for (const [nombre, regla] of Object.entries(mapaReglas)) {
      const input = formulario.elements.namedItem(nombre);
      if (!input) continue;
      const validar = () => mostrarError(input, regla(input.value, formulario));
      input.addEventListener('blur', () => {
        if (input.value) validar();
      });
      input.addEventListener('input', () => {
        if (input.getAttribute('aria-invalid') === 'true') validar();
      });
    }
  }

  /** Pinta los errores por campo que devuelve el servidor (422). */
  function mostrarErroresServidor(formulario, detalles) {
    if (!Array.isArray(detalles)) return;
    for (const { campo, mensaje } of detalles) {
      const input = typeof campo === 'string' ? formulario.elements.namedItem(campo) : null;
      if (input && typeof mensaje === 'string') mostrarError(input, mensaje);
    }
  }

  const Validators = Object.freeze({
    emailRegex,
    passwordRegex,
    nombreRegex,
    textoSeguroRegex,
    montoRegex,
    fechaRegex,
    codigoRegex,
    sanitizeInput,
    limpiarTexto,
    contieneCodigo,
    normalizarMonto,
    validateUserForm,
    validateGastoForm,
    reglas: Object.freeze(reglas),
    mostrarError,
    mostrarErrorGeneral,
    limpiarErrores,
    validarFormulario,
    activarValidacionEnVivo,
    mostrarErroresServidor,
  });

  // Disponible de forma global en el navegador y como módulo en las pruebas de Node.
  if (typeof window !== 'undefined') window.Validators = Validators;
  if (typeof module !== 'undefined' && module.exports) module.exports = Validators;
})();
