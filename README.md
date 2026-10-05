# SSH Runner

Aplicación web local para guardar conexiones SSH (mediante claves privadas), almacenar scripts shell, copiarlos al servidor, ejecutarlos y consultar su salida. También permite editar y eliminar conexiones y scripts existentes.

La interfaz web está organizada en la carpeta `static/`.

## Requisitos

- Python 3.9+
- Cliente `ssh` disponible en el equipo
- Una clave SSH configurada y autorizada en el servidor remoto

## Uso con Docker

Requisitos: Docker Engine y Docker Compose. La imagen incluye Python y el cliente
OpenSSH; no es necesario instalar dependencias en el host.

```bash
docker compose up -d --build
```

Abre <http://127.0.0.1:8080>. Los scripts y credenciales se conservan en
`data/store.json` en el host, montado como `/app/data` dentro del contenedor.
Este archivo se mantiene al reiniciar o recrear el contenedor y puedes
respaldarlo junto con el proyecto.

El directorio `~/.ssh` se monta como solo lectura en `/run/ssh` dentro del
contenedor. Al crear una conexión desde la aplicación, usa por ejemplo
`/run/ssh/id_ed25519` como ruta de clave privada. No uses `/root/.ssh`, ya que
la aplicación se ejecuta con un usuario sin privilegios.

Para detener la aplicación:

```bash
docker compose down
```

No ejecutes `docker compose down -v` esperando conservar datos de Docker
anteriores; la configuración actual usa directamente `./data`, por lo que el
archivo persistente está fuera del ciclo de vida del contenedor.

El servicio solo publica el puerto en `127.0.0.1`. No lo expongas directamente
a Internet.

## Uso

```bash
python3 server.py
```

Abre <http://127.0.0.1:8080>. Los datos se guardan en `data/store.json`, creado con permisos `0600`. La aplicación está pensada para uso local: no la expongas directamente a Internet. Se recomienda usar claves SSH con agente o passphrase y no contraseñas.

El flujo **Copiar y ejecutar** envía el contenido por stdin a un archivo temporal en el servidor, aplica permisos ejecutables, ejecuta `bash` y elimina el archivo aunque el script termine con un código distinto de cero.

Las conexiones pueden usar una ruta a una clave existente o el contenido pegado de
una clave privada. La clave pegada se almacena en `data/store.json`, protegido
con permisos `0600`, y se escribe en un archivo temporal local con permisos
`0600` únicamente durante la conexión.
