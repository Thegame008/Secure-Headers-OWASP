# Contribuir a SafeWebHeaders

1. Conserva cada cambio dentro del módulo que posee la responsabilidad.
2. Añade una prueba de regresión que falle antes del cambio y pase después.
3. No añadas secretos, objetivos privados ni artefactos generados al código.
4. Ejecuta la suite, el compilador, Ruff, mypy y Bandit.
5. Describe aplicabilidad y límites; una cabecera ausente no equivale
   automáticamente a una vulnerabilidad.

Las fachadas `safewebheaders.py` y `mejora.py` existen solo por compatibilidad.
La implementación nueva pertenece al paquete `safewebheaders/`.

