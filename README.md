# chaoswaf
WAF basado en mitigación de CSRF mediante la técnica de caos controlado mediante dispersión de encabezados y otros parámetros. 

ChaosWAF - Sistema de Firewall Distribuido Basado en Caos

ChaosWAF es un sistema de firewall de aplicaciones web (WAF) distribuido que utiliza un enfoque innovador basado en aleatoriedad y caos para proteger aplicaciones web contra ataques maliciosos. Consiste en un servidor central y múltiples clientes que implementan políticas de seguridad descentralizadas.

Características Principales
Arquitectura distribuida: Clientes ligeros que protegen aplicaciones web individuales
Validación K-de-N: Requiere que las solicitudes incluyan K de N tokens válidos en las cabeceras HTTP
Tokens dinámicos: Cabeceras válidas y señuelos generados dinámicamente
Panel de control central: Monitoreo y gestión de todos los clientes
Comunicación segura: TLS opcional con autenticación mutua
Auto-recuperación: Reconexión automática y gestión de errores
Estadísticas en tiempo real: Monitoreo de tráfico y bloqueos

Componentes del Sistema

Servidor Central (server_chaoswaf)
El servidor central gestiona todos los clientes conectados, recibe reportes y permite el control remoto.
Funcionalidades:
Autenticación de clientes mediante tokens
Registro centralizado de eventos
Panel web para monitoreo
API para integraciones
Envío de comandos a clientes
Estadísticas globales

Cliente (chaoswaf_client)
El cliente protege aplicaciones web actuando como proxy inverso con capacidades WAF.
Funcionalidades:
Proxy HTTP/HTTPS local
Validación de solicitudes con esquema K-de-N
Conexión persistente al servidor central
Panel local para monitoreo
Reconexión automática
Reporte de eventos al servidor


Requisitos
Go 1.20 o superior

Permisos de root para puertos bajos (opcional)
go build -o 
