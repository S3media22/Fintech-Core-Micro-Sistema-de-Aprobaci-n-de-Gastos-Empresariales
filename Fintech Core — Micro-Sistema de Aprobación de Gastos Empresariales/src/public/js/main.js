/**
 * Control de vistas, consumo de la API y manipulación del DOM — Sprints Martes a Jueves.
 *
 * Reglas OWASP que cumple este archivo:
 *  - Nunca se usa innerHTML, outerHTML, insertAdjacentHTML ni document.write.
 *    Todo dato del servidor o del usuario se pinta con textContent.
 *  - Los componentes dinámicos se clonan desde <template> del index.html.
 *  - El token de sesión NO existe para JavaScript: vive en una cookie HttpOnly.
 *    sessionStorage solo guarda datos no críticos (nombre, rol, tasa del día, filtro).
 *  - Los parámetros de la URL nunca se pintan directamente: se traducen con una lista blanca.
 */
(function () {
  'use strict';

  const V = window.Validators;
  if (!V) {
    console.error('validators.js no se cargó antes que main.js');
    return;
  }

  /* ================================================================== */
  /* Estado y almacenamiento no crítico                                 */
  /* ================================================================== */
  const CLAVES = Object.freeze({ perfil: 'fc.perfil', tasa: 'fc.tasa', filtro: 'fc.filtro' });
  const TASA_VIGENCIA_MS = 10 * 60 * 1000;

  const Almacen = {
    leer(clave) {
      try {
        const valor = sessionStorage.getItem(clave);
        return valor ? JSON.parse(valor) : null;
      } catch {
        return null;
      }
    },
    guardar(clave, valor) {
      try {
        sessionStorage.setItem(clave, JSON.stringify(valor));
      } catch {
        /* modo privado o cuota llena: la app sigue funcionando sin caché */
      }
    },
    limpiar() {
      for (const clave of Object.values(CLAVES)) {
        try {
          sessionStorage.removeItem(clave);
        } catch {
          /* sin acceso a storage */
        }
      }
    },
  };

  const estado = {
    usuario: null,
    tasa: null,
    filtro: '',
    pendientes: [],
    configurando2FA: false,
  };

  /* ================================================================== */
  /* Utilidades                                                         */
  /* ================================================================== */
  const $ = (selector, raiz = document) => raiz.querySelector(selector);
  const $$ = (selector, raiz = document) => Array.from(raiz.querySelectorAll(selector));
  const campo = (raiz, nombre) => raiz.querySelector(`[data-campo="${nombre}"]`);
  const menosMovimiento = () => window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  const CATEGORIAS = Object.freeze({
    transporte: 'Transporte',
    alimentacion: 'Alimentación',
    hospedaje: 'Hospedaje',
    software: 'Software y licencias',
    equipos: 'Equipos',
    otros: 'Otros',
  });
  const ESTADOS = Object.freeze({ pendiente: 'Pendiente', aprobado: 'Aprobado', rechazado: 'Rechazado' });
  const ESTADOS_PLURAL = Object.freeze({ aprobado: 'Aprobados', pendiente: 'Pendientes', rechazado: 'Rechazados' });
  const FUENTES = Object.freeze({ api: 'en vivo', cache: 'última tasa guardada', respaldo: 'tasa de respaldo' });
  const AVISOS_URL = Object.freeze({
    oauth_error: 'No se pudo iniciar sesión con el proveedor. Inténtalo de nuevo o usa tu correo.',
    oauth_estado: 'La solicitud de inicio de sesión expiró o no es válida. Inténtalo de nuevo.',
  });

  const formatoCOP = new Intl.NumberFormat('es-CO', { style: 'currency', currency: 'COP', minimumFractionDigits: 2 });
  const formatoUSD = new Intl.NumberFormat('es-CO', { style: 'currency', currency: 'USD', minimumFractionDigits: 2 });
  const formatoTasa = new Intl.NumberFormat('es-CO', { minimumFractionDigits: 2, maximumFractionDigits: 2 });
  const formatoFecha = new Intl.DateTimeFormat('es-CO', { day: '2-digit', month: 'short', year: 'numeric' });

  function formatearFecha(iso) {
    return /^\d{4}-\d{2}-\d{2}$/.test(iso) ? formatoFecha.format(new Date(`${iso}T12:00:00`)) : '';
  }

  function fechaLocalIso(fecha = new Date()) {
    return new Date(fecha.getTime() - fecha.getTimezoneOffset() * 60000).toISOString().slice(0, 10);
  }

  /** Crea un elemento asignando solo texto y clases (sin HTML). */
  function crear(etiqueta, { clase, texto } = {}) {
    const elemento = document.createElement(etiqueta);
    if (clase) elemento.className = clase;
    if (texto !== undefined) elemento.textContent = texto;
    return elemento;
  }

  function aplicarSello(elemento, valorEstado) {
    const clave = Object.hasOwn(ESTADOS, valorEstado) ? valorEstado : 'pendiente';
    elemento.classList.remove('sello--pendiente', 'sello--aprobado', 'sello--rechazado');
    elemento.classList.add('sello', `sello--${clave}`);
    elemento.textContent = ESTADOS[clave];
  }

  let temporizadorAviso;
  function avisar(mensaje, tipo = 'info') {
    const aviso = $('#aviso');
    aviso.textContent = mensaje;
    aviso.dataset.tipo = ['info', 'exito', 'error'].includes(tipo) ? tipo : 'info';
    aviso.hidden = false;
    clearTimeout(temporizadorAviso);
    temporizadorAviso = setTimeout(() => {
      aviso.hidden = true;
    }, 6000);
  }

  /** Deshabilita el botón mientras corre la acción para evitar envíos dobles. */
  async function conCarga(boton, accion) {
    if (!boton || boton.disabled) return;
    boton.disabled = true;
    boton.setAttribute('aria-busy', 'true');
    try {
      await accion();
    } finally {
      boton.disabled = false;
      boton.removeAttribute('aria-busy');
    }
  }

  /* ================================================================== */
  /* Cliente de la API (fetch)                                          */
  /* ================================================================== */
  class ErrorApi extends Error {
    constructor(message, statusCode, detalles) {
      super(message);
      this.statusCode = statusCode;
      this.detalles = detalles;
    }
  }

  // En estas rutas un 401 es una respuesta normal (credenciales/código incorrectos), no una sesión expirada.
  const RUTAS_401_ESPERADO = ['/api/auth/login', '/api/auth/register', '/api/auth/2fa/verify', '/api/auth/me'];

  async function api(ruta, { metodo = 'GET', cuerpo } = {}) {
    const opciones = {
      method: metodo,
      credentials: 'same-origin', // envía la cookie HttpOnly; JS nunca la ve
      headers: { Accept: 'application/json' },
    };
    if (cuerpo !== undefined) {
      opciones.headers['Content-Type'] = 'application/json';
      opciones.body = JSON.stringify(cuerpo);
    }

    let respuesta;
    try {
      respuesta = await fetch(ruta, opciones);
    } catch {
      throw new ErrorApi('No hay conexión con el servidor. Revisa tu red e inténtalo de nuevo.', 0);
    }

    let datos = null;
    try {
      datos = await respuesta.json();
    } catch {
      datos = null;
    }

    if (!respuesta.ok || datos?.status !== 'success') {
      if (respuesta.status === 401 && !RUTAS_401_ESPERADO.includes(ruta)) manejarSesionExpirada();
      throw new ErrorApi(datos?.message || 'La solicitud no se pudo completar.', respuesta.status, datos?.detalles);
    }
    return datos;
  }

  /* ================================================================== */
  /* Sesión                                                             */
  /* ================================================================== */
  function establecerUsuario(usuario) {
    estado.usuario = usuario;
    Almacen.guardar(CLAVES.perfil, { nombre: usuario.nombre, rol: usuario.rol });
  }

  async function cargarSesion() {
    try {
      const { data } = await api('/api/auth/me');
      establecerUsuario(data.usuario);
      return true;
    } catch {
      estado.usuario = null;
      Almacen.limpiar();
      return false;
    }
  }

  function limpiarDatosPanel() {
    $('#tabla-gastos').replaceChildren();
    $('#totales').replaceChildren();
    $('#lista-pendientes').replaceChildren();
    $('#cuentas').replaceChildren();
    $('#qr-2fa').removeAttribute('src');
    $('#clave-manual').textContent = '';
    estado.pendientes = [];
    estado.tasa = null;
    estado.configurando2FA = false;
  }

  let expirando = false;
  function manejarSesionExpirada() {
    if (expirando || !estado.usuario) return;
    expirando = true;
    estado.usuario = null;
    Almacen.limpiar();
    limpiarDatosPanel();
    avisar('Tu sesión expiró. Inicia sesión de nuevo.', 'error');
    navegar('login');
    setTimeout(() => {
      expirando = false;
    }, 500);
  }

  async function cerrarSesion() {
    try {
      await api('/api/auth/logout', { metodo: 'POST' });
    } catch {
      /* aunque falle la red, se limpia el cliente */
    }
    estado.usuario = null;
    Almacen.limpiar();
    limpiarDatosPanel();
    navegar('login');
    avisar('Cerraste sesión.', 'info');
  }

  /* ================================================================== */
  /* Enrutador por hash (alterna Login ↔ Dashboard sin recargar)        */
  /* ================================================================== */
  const PANELES_ACCESO = new Set(['login', 'registro', 'verificar']);
  const SECCIONES_PANEL = Object.freeze({
    panel: 'seccion-gastos',
    aprobaciones: 'seccion-aprobaciones',
    seguridad: 'seccion-seguridad',
  });

  function navegar(ruta) {
    if (location.hash === `#${ruta}`) renderizar();
    else location.hash = ruta;
  }

  async function renderizar() {
    let ruta = location.hash.replace(/^#/, '');

    if (PANELES_ACCESO.has(ruta)) {
      if (ruta !== 'verificar' && estado.usuario) return navegar('panel');
      return mostrarAcceso(ruta);
    }

    if (!Object.hasOwn(SECCIONES_PANEL, ruta)) ruta = 'panel';
    if (!estado.usuario && !(await cargarSesion())) return navegar('login');
    if (ruta === 'aprobaciones' && estado.usuario.rol !== 'aprobador') return navegar('panel');

    mostrarPanel(ruta);
  }

  function mostrarAcceso(panel) {
    $('#vista-panel').hidden = true;
    $('#vista-acceso').hidden = false;
    for (const seccion of $$('[data-panel]')) seccion.hidden = seccion.dataset.panel !== panel;

    const titulos = { login: 'Inicia sesión', registro: 'Crea tu cuenta', verificar: 'Verificación' };
    document.title = `${titulos[panel]} | Fintech Core`;
    $(`[data-panel="${panel}"] input`)?.focus();
  }

  function mostrarPanel(ruta) {
    $('#vista-acceso').hidden = true;
    $('#vista-panel').hidden = false;

    pintarEncabezado();
    for (const pestana of $$('[role="tab"]')) {
      const activa = pestana.dataset.ruta === ruta;
      pestana.setAttribute('aria-selected', String(activa));
      pestana.tabIndex = activa ? 0 : -1;
    }
    for (const [nombre, id] of Object.entries(SECCIONES_PANEL)) $(`#${id}`).hidden = nombre !== ruta;

    const titulos = { panel: 'Mis gastos', aprobaciones: 'Por aprobar', seguridad: 'Seguridad' };
    document.title = `${titulos[ruta]} | Fintech Core`;

    cargarTasa();
    if (estado.usuario.rol === 'aprobador') cargarPendientes();
    if (ruta === 'panel') cargarGastos();
    if (ruta === 'seguridad') pintarSeguridad();
  }

  function pintarEncabezado() {
    const { nombre, rol } = estado.usuario;
    $('#usuario-nombre').textContent = nombre;
    $('#usuario-rol').textContent = rol === 'aprobador' ? 'Aprobador' : 'Empleado';
    $('#pestana-aprobaciones').hidden = rol !== 'aprobador';
  }

  /* ================================================================== */
  /* Tasa de cambio (microservicio)                                     */
  /* ================================================================== */
  async function cargarTasa({ forzar = false } = {}) {
    const guardada = Almacen.leer(CLAVES.tasa);
    if (!forzar && guardada?.tasa && Date.now() - guardada.guardadaEn < TASA_VIGENCIA_MS) {
      estado.tasa = guardada.tasa;
      return pintarTasa();
    }
    try {
      const { data } = await api('/api/gastos/tasa');
      estado.tasa = data.tasa;
      Almacen.guardar(CLAVES.tasa, { tasa: data.tasa, guardadaEn: Date.now() });
      pintarTasa();
    } catch {
      $('#tasa-valor').textContent = 'No disponible';
      $('#tasa-fuente').textContent = '';
    }
  }

  function pintarTasa() {
    const tasa = estado.tasa;
    if (!tasa || !Number.isFinite(Number(tasa.tasa))) return;
    $('#tasa-valor').textContent = `US$ 1 = ${formatoCOP.format(Number(tasa.tasa))}`;
    $('#tasa-fuente').textContent = FUENTES[tasa.fuente] || '';
    $('#tasa').dataset.fuente = Object.hasOwn(FUENTES, tasa.fuente) ? tasa.fuente : '';
    actualizarConversion();
  }

  function actualizarConversion() {
    const salida = $('#conversion');
    const monto = V.normalizarMonto($('#gasto-monto').value);

    if (!monto) {
      salida.textContent = 'Escribe el monto para ver el valor aproximado en pesos.';
      return;
    }
    if (V.reglas.montoEnUSD(monto) || !estado.tasa) {
      salida.textContent = estado.tasa ? 'Revisa el monto para calcular la conversión.' : 'La tasa del día no está disponible en este momento.';
      return;
    }
    const aproximado = Number(monto) * Number(estado.tasa.tasa);
    salida.textContent = `Aproximadamente ${formatoCOP.format(aproximado)} con la tasa actual. El valor final se fija al enviar.`;
  }

  /* ================================================================== */
  /* Mis gastos                                                         */
  /* ================================================================== */
  async function cargarGastos() {
    const cuerpo = $('#tabla-gastos');
    cuerpo.setAttribute('aria-busy', 'true');
    try {
      const consulta = estado.filtro ? `?estado=${encodeURIComponent(estado.filtro)}` : '';
      const { data } = await api(`/api/gastos${consulta}`);
      pintarGastos(data.gastos);
      pintarTotales(data.resumen);
    } catch (error) {
      if (error.statusCode !== 401) avisar(error.message, 'error');
    } finally {
      cuerpo.removeAttribute('aria-busy');
    }
  }

  function detalleGasto(gasto) {
    const respaldo = gasto.fuenteTasa === 'respaldo' ? ' (respaldo)' : '';
    const partes = [CATEGORIAS[gasto.categoria] || 'Otros', `tasa ${formatoTasa.format(Number(gasto.tasaCambio))}${respaldo}`];
    if (gasto.estado === 'aprobado' && gasto.aprobador) partes.push(`aprobó ${gasto.aprobador}`);
    if (gasto.estado === 'rechazado' && gasto.comentarioAprobador) partes.push(`motivo: ${gasto.comentarioAprobador}`);
    return partes.join(', ');
  }

  function pintarGastos(gastos) {
    const plantilla = $('#tpl-fila-gasto');
    const filas = gastos.map((gasto) => {
      const fila = plantilla.content.firstElementChild.cloneNode(true);
      campo(fila, 'fecha').textContent = formatearFecha(gasto.fechaGasto);
      campo(fila, 'descripcion').textContent = gasto.descripcion;
      campo(fila, 'detalle').textContent = detalleGasto(gasto);
      campo(fila, 'usd').textContent = formatoUSD.format(Number(gasto.montoUsd));
      campo(fila, 'cop').textContent = formatoCOP.format(Number(gasto.montoCop));
      aplicarSello(campo(fila, 'estado'), gasto.estado);
      return fila;
    });

    $('#tabla-gastos').replaceChildren(...filas);

    const vacio = $('#gastos-vacio');
    vacio.hidden = filas.length > 0;
    vacio.textContent = estado.filtro
      ? `No tienes gastos ${ESTADOS_PLURAL[estado.filtro].toLowerCase()}.`
      : 'Aún no registras gastos. Usa el formulario para enviar el primero.';
  }

  function pintarTotales(resumen) {
    const grupos = ['aprobado', 'pendiente', 'rechazado'].map((clave) => {
      const datos = resumen?.[clave] || { cantidad: 0, totalCop: '0' };
      const grupo = crear('div', { clase: `total total--${clave}` });
      grupo.append(
        crear('dt', { texto: ESTADOS_PLURAL[clave] }),
        crear('dd', { clase: 'total__cantidad', texto: `${datos.cantidad} ${datos.cantidad === 1 ? 'gasto' : 'gastos'}` }),
        crear('dd', { clase: 'total__monto cifra', texto: formatoCOP.format(Number(datos.totalCop)) })
      );
      return grupo;
    });
    $('#totales').replaceChildren(...grupos);
  }

  function prepararFiltros() {
    const guardado = Almacen.leer(CLAVES.filtro);
    estado.filtro = Object.hasOwn(ESTADOS, guardado) ? guardado : '';

    const sincronizar = () => {
      for (const boton of $$('.filtro')) boton.setAttribute('aria-pressed', String(boton.dataset.estado === estado.filtro));
    };
    sincronizar();

    for (const boton of $$('.filtro')) {
      boton.addEventListener('click', () => {
        estado.filtro = boton.dataset.estado;
        Almacen.guardar(CLAVES.filtro, estado.filtro);
        sincronizar();
        cargarGastos();
      });
    }
    return sincronizar;
  }

  function prepararFormularioGasto(sincronizarFiltros) {
    const formulario = $('#form-gasto');
    const inputFecha = $('#gasto-fecha');
    const reglas = {
      descripcion: V.reglas.descripcion,
      categoria: V.reglas.categoria,
      montoEnUSD: V.reglas.montoEnUSD,
      fechaGasto: V.reglas.fechaGasto,
    };

    const reiniciarFecha = () => {
      inputFecha.max = fechaLocalIso();
      inputFecha.min = fechaLocalIso(new Date(Date.now() - 365 * 86400000));
      inputFecha.value = fechaLocalIso();
    };
    reiniciarFecha();

    V.activarValidacionEnVivo(formulario, reglas);
    $('#gasto-monto').addEventListener('input', actualizarConversion);

    formulario.addEventListener('submit', (evento) => {
      evento.preventDefault();
      V.mostrarErrorGeneral(formulario, '');
      if (!V.validarFormulario(formulario, reglas)) return;

      const boton = formulario.querySelector('[type="submit"]');
      conCarga(boton, async () => {
        try {
          const respuesta = await api('/api/gastos', {
            metodo: 'POST',
            cuerpo: {
              descripcion: V.limpiarTexto(formulario.elements.descripcion.value),
              categoria: formulario.elements.categoria.value,
              montoEnUSD: V.normalizarMonto(formulario.elements.montoEnUSD.value),
              fechaGasto: formulario.elements.fechaGasto.value,
            },
          });

          formulario.reset();
          V.limpiarErrores(formulario);
          reiniciarFecha();
          actualizarConversion();

          const { montoFinalCOP, fuenteTasa } = respuesta.data;
          const nota = fuenteTasa === 'api' ? '' : ' Se usó una tasa de respaldo porque el servicio de divisas no respondió.';
          avisar(`Gasto enviado a aprobación por ${formatoCOP.format(Number(montoFinalCOP))}.${nota}`, 'exito');

          if (estado.filtro && estado.filtro !== 'pendiente') {
            estado.filtro = '';
            Almacen.guardar(CLAVES.filtro, '');
            sincronizarFiltros();
          }
          cargarGastos();
          formulario.elements.descripcion.focus();
        } catch (error) {
          V.mostrarErroresServidor(formulario, error.detalles);
          V.mostrarErrorGeneral(formulario, error.message);
        }
      });
    });
  }

  /* ================================================================== */
  /* Bandeja del aprobador                                              */
  /* ================================================================== */
  async function cargarPendientes() {
    try {
      const { data } = await api('/api/gastos/pendientes');
      estado.pendientes = data.gastos;
      pintarPendientes();
    } catch (error) {
      if (error.statusCode !== 401) avisar(error.message, 'error');
    }
  }

  function pintarPendientes() {
    const items = estado.pendientes.map(crearItemPendiente);
    $('#lista-pendientes').replaceChildren(...items);
    $('#pendientes-vacio').hidden = items.length > 0;

    const contador = $('#contador-pendientes');
    contador.hidden = items.length === 0;
    contador.textContent = String(items.length);
  }

  function crearItemPendiente(gasto) {
    const item = $('#tpl-pendiente').content.firstElementChild.cloneNode(true);
    const idBase = `comentario-${Number(gasto.id)}`;

    campo(item, 'descripcion').textContent = gasto.descripcion;
    campo(item, 'meta').textContent = [
      gasto.solicitante,
      formatearFecha(gasto.fechaGasto),
      CATEGORIAS[gasto.categoria] || 'Otros',
    ].join(', ');
    campo(item, 'usd').textContent = formatoUSD.format(Number(gasto.montoUsd));
    campo(item, 'cop').textContent = formatoCOP.format(Number(gasto.montoCop));

    const etiqueta = campo(item, 'label-comentario');
    const input = campo(item, 'input-comentario');
    const error = campo(item, 'error-comentario');
    input.id = idBase;
    error.id = `${idBase}-error`;
    etiqueta.htmlFor = idBase;

    const formulario = item.querySelector('form');
    for (const boton of formulario.querySelectorAll('button')) {
      boton.addEventListener('click', () => {
        formulario.dataset.decision = boton.value; // respaldo si el navegador no soporta event.submitter
      });
    }
    formulario.addEventListener('submit', (evento) => decidirGasto(evento, gasto, item));
    return item;
  }

  async function decidirGasto(evento, gasto, item) {
    evento.preventDefault();
    const formulario = evento.currentTarget;
    const decision = evento.submitter?.value || formulario.dataset.decision;
    if (decision !== 'aprobado' && decision !== 'rechazado') return;

    const input = campo(item, 'input-comentario');
    const comentario = V.limpiarTexto(input.value);
    const mensaje = V.reglas.comentario(comentario, decision);
    V.mostrarError(input, mensaje);
    if (mensaje) return input.focus();

    const botones = formulario.querySelectorAll('button');
    botones.forEach((b) => (b.disabled = true));

    try {
      const respuesta = await api(`/api/gastos/${encodeURIComponent(gasto.id)}/estado`, {
        metodo: 'PATCH',
        cuerpo: { estado: decision, ...(comentario ? { comentario } : {}) },
      });

      // Respuesta a la acción: el sello cae sobre el gasto y luego sale de la bandeja.
      const sello = campo(item, 'sello');
      aplicarSello(sello, decision);
      sello.hidden = false;
      item.classList.add('pendiente--decidido');
      item.dataset.decision = decision;
      avisar(respuesta.message, 'exito');

      setTimeout(
        () => {
          estado.pendientes = estado.pendientes.filter((p) => p.id !== gasto.id);
          pintarPendientes();
        },
        menosMovimiento() ? 600 : 1300
      );
    } catch (error) {
      botones.forEach((b) => (b.disabled = false));
      if (error.statusCode === 401) return;
      if (Array.isArray(error.detalles)) {
        const detalle = error.detalles.find((d) => d.campo === 'comentario');
        if (detalle) V.mostrarError(input, detalle.mensaje);
      }
      avisar(error.message, 'error');
      if (error.statusCode === 404 || error.statusCode === 409) cargarPendientes();
    }
  }

  /* ================================================================== */
  /* Seguridad: 2FA con código QR                                       */
  /* ================================================================== */
  function pintarSeguridad() {
    const usuario = estado.usuario;
    const activo = Boolean(usuario.dosPasosActivo);

    const sello = $('#estado-2fa');
    sello.classList.remove('sello--aprobado', 'sello--pendiente');
    sello.classList.add(activo ? 'sello--aprobado' : 'sello--pendiente');
    sello.textContent = activo ? 'Activa' : 'Inactiva';

    $('#dospasos-activo').hidden = !activo;
    $('#dospasos-inactivo').hidden = activo || estado.configurando2FA;
    $('#dospasos-configurar').hidden = activo || !estado.configurando2FA;

    const cuentas = [
      ['Correo y contraseña', usuario.tienePassword ? 'Configurada' : 'Sin contraseña: entras con un proveedor'],
      ['Google', usuario.googleVinculado ? 'Vinculada' : 'No vinculada'],
      ['GitHub', usuario.githubVinculado ? 'Vinculada' : 'No vinculada'],
    ].map(([nombre, valor]) => {
      const fila = crear('div', { clase: 'cuentas__fila' });
      fila.append(crear('dt', { texto: nombre }), crear('dd', { texto: valor }));
      return fila;
    });
    $('#cuentas').replaceChildren(...cuentas);
  }

  function cancelarConfiguracion2FA() {
    estado.configurando2FA = false;
    $('#qr-2fa').removeAttribute('src');
    $('#clave-manual').textContent = '';
    const formulario = $('#form-2fa-activar');
    formulario.reset();
    V.limpiarErrores(formulario);
    pintarSeguridad();
  }

  function prepararSeguridad() {
    const botonConfigurar = $('#btn-2fa-configurar');
    botonConfigurar.addEventListener('click', () =>
      conCarga(botonConfigurar, async () => {
        try {
          const { data } = await api('/api/auth/2fa/setup', { metodo: 'POST' });
          // Solo se acepta una imagen PNG en base64: nada de URLs arbitrarias en el src.
          if (!/^data:image\/png;base64,[A-Za-z0-9+/=]+$/.test(data.qr)) throw new ErrorApi('El código QR recibido no es válido.', 500);

          $('#qr-2fa').src = data.qr;
          $('#clave-manual').textContent = String(data.claveManual).replace(/(.{4})(?=.)/g, '$1 ');
          estado.configurando2FA = true;
          pintarSeguridad();
          $('#activar-code').focus();
        } catch (error) {
          if (error.statusCode !== 401) avisar(error.message, 'error');
        }
      })
    );

    $('#btn-2fa-cancelar').addEventListener('click', cancelarConfiguracion2FA);

    enlazarFormularioCodigo($('#form-2fa-activar'), '/api/auth/2fa/enable', (data, mensaje) => {
      establecerUsuario(data.usuario);
      cancelarConfiguracion2FA();
      avisar(mensaje, 'exito');
    });

    enlazarFormularioCodigo($('#form-2fa-desactivar'), '/api/auth/2fa/disable', (data, mensaje) => {
      establecerUsuario(data.usuario);
      pintarSeguridad();
      avisar(mensaje, 'info');
    });
  }

  /** Formularios de un único campo "code" (6 dígitos). */
  function enlazarFormularioCodigo(formulario, ruta, alExito) {
    const input = formulario.elements.namedItem('code');
    input.addEventListener('input', () => {
      input.value = input.value.replace(/\D/g, '').slice(0, 6);
    });

    formulario.addEventListener('submit', (evento) => {
      evento.preventDefault();
      V.mostrarErrorGeneral(formulario, '');
      if (!V.validarFormulario(formulario, { code: V.reglas.code })) return;

      conCarga(formulario.querySelector('[type="submit"]'), async () => {
        try {
          const respuesta = await api(ruta, { metodo: 'POST', cuerpo: { code: input.value } });
          formulario.reset();
          alExito(respuesta.data || {}, respuesta.message);
        } catch (error) {
          if (error.statusCode === 401 && !RUTAS_401_ESPERADO.includes(ruta)) return;
          V.mostrarErroresServidor(formulario, error.detalles);
          V.mostrarErrorGeneral(formulario, error.message);
          input.select();
        }
      });
    });
  }

  /* ================================================================== */
  /* Acceso: login, registro, 2FA y OAuth                               */
  /* ================================================================== */
  function prepararAcceso() {
    const formLogin = $('#form-login');
    const reglasLogin = { email: V.reglas.email, password: V.reglas.passwordLogin };
    V.activarValidacionEnVivo(formLogin, reglasLogin);

    formLogin.addEventListener('submit', (evento) => {
      evento.preventDefault();
      V.mostrarErrorGeneral(formLogin, '');
      if (!V.validarFormulario(formLogin, reglasLogin)) return;

      conCarga(formLogin.querySelector('[type="submit"]'), async () => {
        try {
          const { data } = await api('/api/auth/login', {
            metodo: 'POST',
            cuerpo: {
              email: V.limpiarTexto(formLogin.elements.email.value).toLowerCase(),
              password: formLogin.elements.password.value,
            },
          });
          formLogin.reset();
          if (data.requiere2FA) return navegar('verificar');
          establecerUsuario(data.usuario);
          navegar('panel');
        } catch (error) {
          formLogin.elements.password.value = '';
          V.mostrarErroresServidor(formLogin, error.detalles);
          V.mostrarErrorGeneral(formLogin, error.message);
        }
      });
    });

    const formRegistro = $('#form-registro');
    const reglasRegistro = {
      nombre: V.reglas.nombre,
      email: V.reglas.email,
      password: V.reglas.password,
      passwordConfirm: V.reglas.passwordConfirm,
    };
    V.activarValidacionEnVivo(formRegistro, reglasRegistro);

    formRegistro.addEventListener('submit', (evento) => {
      evento.preventDefault();
      V.mostrarErrorGeneral(formRegistro, '');
      if (!V.validarFormulario(formRegistro, reglasRegistro)) return;

      conCarga(formRegistro.querySelector('[type="submit"]'), async () => {
        try {
          const { data, message } = await api('/api/auth/register', {
            metodo: 'POST',
            cuerpo: {
              nombre: V.limpiarTexto(formRegistro.elements.nombre.value),
              email: V.limpiarTexto(formRegistro.elements.email.value).toLowerCase(),
              password: formRegistro.elements.password.value,
              passwordConfirm: formRegistro.elements.passwordConfirm.value,
            },
          });
          formRegistro.reset();
          establecerUsuario(data.usuario);
          navegar('panel');
          avisar(`${message} Te recomendamos activar la verificación en dos pasos en Seguridad.`, 'exito');
        } catch (error) {
          V.mostrarErroresServidor(formRegistro, error.detalles);
          V.mostrarErrorGeneral(formRegistro, error.message);
        }
      });
    });

    enlazarFormularioCodigo($('#form-verificar'), '/api/auth/2fa/verify', (data) => {
      establecerUsuario(data.usuario);
      navegar('panel');
    });
  }

  async function cargarProveedores() {
    try {
      const { data } = await api('/api/auth/providers');
      const { google, github } = data.proveedores || {};
      $('#oauth-google').hidden = !google;
      $('#oauth-github').hidden = !github;
      $('#oauth').hidden = !(google || github);
    } catch {
      $('#oauth').hidden = true;
    }
  }

  function prepararPestanas() {
    const pestanas = () => $$('[role="tab"]').filter((p) => !p.hidden);

    for (const pestana of $$('[role="tab"]')) {
      pestana.addEventListener('click', () => navegar(pestana.dataset.ruta));
      pestana.addEventListener('keydown', (evento) => {
        if (evento.key !== 'ArrowRight' && evento.key !== 'ArrowLeft') return;
        const visibles = pestanas();
        const indice = visibles.indexOf(pestana);
        const siguiente = visibles[(indice + (evento.key === 'ArrowRight' ? 1 : -1) + visibles.length) % visibles.length];
        siguiente.focus();
        navegar(siguiente.dataset.ruta);
      });
    }
    $('#btn-salir').addEventListener('click', cerrarSesion);
  }

  /** Avisos que llegan por URL (?aviso=...) tras OAuth: se traducen con lista blanca y se limpian. */
  function leerAvisoDeUrl() {
    const parametros = new URLSearchParams(location.search);
    const clave = parametros.get('aviso');
    if (clave && Object.hasOwn(AVISOS_URL, clave)) avisar(AVISOS_URL[clave], 'error');
    if (parametros.has('aviso')) history.replaceState(null, '', `${location.pathname}${location.hash}`);
  }

  /* ================================================================== */
  /* Arranque                                                           */
  /* ================================================================== */
  async function iniciar() {
    const sincronizarFiltros = prepararFiltros();
    prepararAcceso();
    prepararFormularioGasto(sincronizarFiltros);
    prepararSeguridad();
    prepararPestanas();
    leerAvisoDeUrl();

    window.addEventListener('hashchange', renderizar);

    await Promise.all([cargarProveedores(), cargarSesion()]);
    renderizar();
  }

  iniciar();
})();
