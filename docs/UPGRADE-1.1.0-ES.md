# Actualizar Cachaza 1.1.0 en GitHub y Kali

Los cambios están preparados en la rama `feat/audit-quality-1.1.0` del repositorio local `cachaza-release`. Publicar esa rama no actualiza `main`: primero se integra el pull request y después se publica la etiqueta. Los informes de ejemplo no forman parte del código ni del paquete.

## 1. Publicar la rama desde Windows

En PowerShell:

```powershell
Set-Location 'C:\Users\skval\OneDrive\Codex\cachaza+origin\cachaza-release'
git status --short
git branch --show-current
git push -u origin feat/audit-quality-1.1.0
```

Abre la comparación en GitHub:

[Crear el pull request hacia main](https://github.com/W4RRR/cachaza/compare/main...feat/audit-quality-1.1.0)

Usa como título `Cachaza 1.1.0: audit comparison, review workflow and evidence quality`. Puedes copiar la descripción de `docs/PR-1.1.0.md`. Espera a que termine `Pull request checks` y revisa el diff antes de integrar el PR con **Merge** o **Squash and merge**.

## 2. Publicar la versión estable

Después de integrar el PR, desde el mismo repositorio de Windows:

```powershell
git switch main
git pull --ff-only origin main
git status --short
git tag -a v1.1.0 -m 'Cachaza v1.1.0'
git push origin v1.1.0
```

El estado debe estar limpio antes de crear la etiqueta. Si `git pull --ff-only` o la creación de la etiqueta falla, detente y revisa la causa; no fuerces la rama ni reemplaces una etiqueta publicada. El workflow `Publish release` comprueba la versión, ejecuta los tests, construye el wheel y crea la Release pública. Espera a que termine y comprueba que GitHub muestra `v1.1.0` como Latest antes de usar el actualizador sin checkout.

## 3. Actualizar en Kali

Desde el directorio donde tengas el checkout de Cachaza:

```bash
cachaza -up
cachaza -version
cachaza doctor
```

La versión esperada es `cachaza 1.1.0`. Si prefieres actualizar manualmente un checkout, ejecuta desde su directorio:

```bash
git status --short
git switch main
git pull --ff-only origin main
pipx install --force .
cachaza -version
cachaza doctor
```

Si el estado muestra cambios locales, consérvalos antes de actualizar. No uses `git reset --hard`. `doctor` indica disponibilidad de herramientas y presencia de credenciales; no confirma que una API acepte la cuenta.

Sin checkout puedes instalar la etiqueta estable exacta, una vez publicada:

```bash
pipx install --force 'git+https://github.com/W4RRR/cachaza.git@v1.1.0'
cachaza -version
```

## 4. Usar las mejoras

Regenerar un informe existente sin hacer peticiones a objetivos ni proveedores:

```bash
cachaza report output/mi-auditoria -professional-report -format html -format pdf -format json -format txt
```

Se necesitan `rest/scope.json` y `rest/findings.jsonl`, además de los artefactos de las etapas que quieras mostrar. Conserva una copia del informe anterior si quieres compararlo: `report` reemplaza los formatos solicitados. Este comando genera contenido determinista; no vuelve a pedir un resumen a OpenRouter ni reutiliza el antiguo.

Comparar dos auditorías con el mismo alcance explícito:

```bash
cachaza diff output/auditoria-anterior output/auditoria-actual -o cambios.json
```

Ambas carpetas deben contener `report.json`. `not_observed` significa que una evidencia ya no aparece; no demuestra que el problema esté resuelto. Revisa cobertura, errores de proveedores y antigüedad en ambos lados. Usa carpetas distintas por fecha para conservar comparaciones históricas.

Listar y registrar decisiones:

```bash
cachaza review output/auditoria-actual
cachaza review output/auditoria-actual -id ID_MOSTRADO -state confirmed -owner 'Equipo de seguridad' -notes 'Evidencia revisada'
cachaza review output/auditoria-actual -id ID_MOSTRADO -state resolved -closure-test 'Retest externo denegado; evidencia en ticket SEC-123'
cachaza report output/auditoria-actual -format html -format pdf -format json
```

Sustituye `ID_MOSTRADO` por el identificador de 24 caracteres que imprime el primer comando. Las decisiones se guardan en `rest/review.json` con historial y no cambian la evidencia del escáner. Los estados disponibles son `pending`, `confirmed`, `dismissed` y `resolved`. La cola se consulta y filtra en HTML; se actualiza con el comando `review`.

Actualizar selectivamente una ejecución pasiva existente:

```bash
cachaza run -d example.com -profile passive -o mi-auditoria -refresh-stages ct
```

La etapa debe estar seleccionada en esa ejecución. También se invalidan los checkpoints posteriores para no reutilizar resultados derivados de entradas antiguas. Solo se ejecutan las etapas seleccionadas para esa invocación, con los controles de autorización habituales. Añade las opciones de autorización originales al refrescar una ejecución activa.

La caducidad predeterminada es 1 hora para DNS/HTTP/puertos/Origin/WAF, 7 días para ASN/cloud y 24 horas para el resto. `-cache-max-age-hours N` permite cambiarla; `0` fuerza la actualización. Al cambiar de versión, las claves de caché se invalidan. Para cambiar únicamente la presentación usa `report`, que no ejecuta etapas.

## Compatibilidad y límites

- JSON añade `schema_version: 2`, `correlation_score`, `score_scale`, `coverage` y `review_queue`. Los campos antiguos `origin_probability*` permanecen como alias obsoletos; no son probabilidades estadísticas.
- Los valores originales siguen disponibles en la evidencia. La normalización de teléfonos afecta a los resúmenes y el extractor filtra nuevos falsos positivos conocidos.
- Los estados `completed` y `cached` describen ejecución/reutilización, no cobertura total. La tabla de cobertura muestra también registros y resultados de proveedores. En workspaces antiguos, la fecha de colección puede aparecer como desconocida.
- El HTML muestra 100 evidencias por página y conserva los datos completos. El grafo mantiene sus controles de agrupación existentes.
- Censys e IntelX siguen necesitando permisos y credenciales válidas. El código no puede conceder acceso a endpoints ni corregir una clave de cuenta.
- Los tests usan fixtures, mocks y ejecuciones sin escaneo. Las comprobaciones locales de esta entrega se hicieron en Windows; el workflow comprueba Linux y varias versiones de Python al publicarse el PR. La ejecución real con herramientas instaladas se verifica en tu Kali con `doctor` y tu siguiente auditoría autorizada.

## Alternativa con paquete local

El ZIP de entrega contiene solo código versionado. Tras extraerlo puedes instalarlo en Kali desde su carpeta con `pipx install --force .`. Para continuar recibiendo actualizaciones usa el checkout de GitHub o la instalación de la etiqueta estable indicada arriba; un ZIP extraído no incorpora historial Git.
