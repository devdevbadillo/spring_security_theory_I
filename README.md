# Spring Security

## Tabla de Contenido

- [Fundamentos de seguridad en aplicaciones web](#fundamentos-de-seguridad-en-aplicaciones)
  - [Autenticación vs. Autorización](#autenticacion-vs-autorizacion)
  - [Principios de seguridad (Acrónimo CIA)](#principios-de-seguridad)
    - [Confidencialidad](#confidencialidad)
    - [Integridad](#integridad)
    - [Disponibilidad](#disponibilidad)
  - [Vulnerabilidades comunes (OWASP Top 10)](#owasp-top-10)
    - [Inyección (SQL Injection, Command Injection)](#injection)
    - [Broken authentication](#broken-autentication)
    - [Sensitive data exposure](#sensitive-data-exposure)
    - [Broken access control](#broken-access-control)
    - [Cross-Site scripting (XSS)](#cross-site-scripting)
    - [Cross-Site request forgery (XSRF)](#cross-site-reques-forgery)
    - [Insecure deserialization](#insecure-deserialization)
  - [Criptografía básica](#criptografia-basica)
    - [Cifrado simétrico y asímetrico](#cifrado-simetrico-y-asimetrico)
  - [Hashing](#hashing)
    - [MD5](#md5)
    - [BCrypt](#bcrypt)
    - [SHA-256](#sha-256)

<a id="fundamentos-de-seguridad-en-aplicaciones"></a>
## Fundamentos de seguridad en aplicaciones web 
La seguridad en aplicaciones web se refiere a las medidas y prácticas implementadas para proteger las aplicaciones basadas en la web de amenazas que puedan comprometer su funcionamiento, la confidencialidad de los datos, la integridad de la información y la disponibilidad de los servicios.

Los ciberataques contra aplicaciones web son variados y en constante evolución. Pueden ir desde inyecciones SQL que buscan manipular bases de datos, hasta ataques de Cross-Site Scripting (XSS) que roban cookies de sesión, pasando por ataques de denegación de servicio (DoS/DDoS) que buscan colapsar los servidores. Por ello, entender los fundamentos de seguridad es el primer paso para construir aplicaciones robustas y resilientes.

<a id="autenticacion-vs-autorizacion"></a>
### Autenticación vs Autorización

Estos dos términos, a menudo confundidos, son pilares de la seguridad en aplicaciones web y, en general, en sistemas de información. Aunque están relacionados, representan procesos distintos y con objetivos diferentes.

> Autenticación

La autenticación es el proceso de **verificar la identidad de un usuario, dispositivo o entidad que intenta acceder a un sistema o recurso**. En esencia, responde a la pregunta: **"¿Eres quien dices ser?"**

El objetivo principal de la autenticación es asegurarse de que solo las personas o entidades legítimas puedan interactuar con el sistema. Los métodos de autenticación comunes incluyen:

* `Contraseñas`: El método más extendido, donde el usuario introduce una cadena secreta que solo él debería conocer. La robustez de una contraseña es clave, y se recomienda el uso de contraseñas fuertes, únicas y el almacenamiento seguro (hash y salt).

* `Tokens de seguridad (OTP, OAuth, JWT) `: Códigos generados una sola vez (OTP - One-Time Password) o tokens criptográficos (como OAuth para delegar acceso sin compartir credenciales directas, o JWT - JSON Web Tokens para representar reclamos entre dos partes) que se utilizan para verificar la identidad.

*  `Autenticación de dos factores (2FA) / Multifactor (MFA)`: Requiere que el usuario proporcione dos o más factores de autenticación independientes para verificar su identidad. Estos factores suelen clasificarse en:
  > 1. Algo que sabes: Contraseña, PIN.
  > 2. Algo que tienes: Teléfono móvil (para OTP vía SMS o app), token físico, tarjeta inteligente.
  > 3. Algo que eres: Biometría (huella dactilar, reconocimiento facial, escaneo de iris). La 2FA/MFA aumenta significativamente la seguridad, ya que incluso si un atacante obtiene un factor (por ejemplo, la contraseña), necesitaría el segundo factor para acceder.


> Autorización

La autorización es el proceso de determinar qué acciones o recursos puede acceder un usuario o entidad autenticada. En esencia, responde a la pregunta: **"¿Qué se te permite hacer?"**

Una vez que un usuario ha sido autenticado, la autorización entra en juego para controlar su nivel de acceso dentro de la aplicación. Por ejemplo, un usuario podría estar autenticado como un "administrador", lo que le autoriza a realizar acciones como añadir nuevos usuarios, modificar configuraciones o eliminar contenido. Un "usuario normal", aunque autenticado, no tendría esas autorizaciones.

Los modelos comunes para implementar la autorización incluyen:

* `Control de Acceso Basado en Roles (RBAC - Role-Based Access Control)`: A los usuarios se les asignan roles (ej. "Administrador", "Editor", "Lector"), y a cada rol se le conceden ciertos permisos. Esto simplifica la gestión, ya que **los permisos se gestionan a nivel de rol, no a nivel de usuario individual**.
* `Control de Acceso Discrecional (DAC - Discretionary Access Control)`: El propietario de un recurso tiene el control sobre quién puede acceder a él y qué permisos tienen. Común en sistemas de archivos donde el propietario de un archivo decide quién puede leerlo, escribirlo o ejecutarlo.

<a id="principios-de-seguridad"></a>
### Principios de seguridad (Acrónimo CIA)
El acrónimo CIA (Confidencialidad, Integridad, Disponibilidad) representa los tres objetivos principales que cualquier medida de seguridad busca lograr para proteger la información.

<a id="confidencialidad"></a>
#### Confidencialidad
La confidencialidad se refiere a la **protección de la información contra el acceso no autorizado o la divulgación a entidades no autorizadas**.

La confidencialidad es crucial para proteger datos sensibles como información personal identificable (PII), secretos comerciales, datos financieros, registros médicos o cualquier otra información que, si se divulgara, podría causar daño a individuos, organizaciones o gobiernos.

> Medidas para garantizar la confidencialidad

1.  `Cifrado de datos `: La conversión de datos a un formato ilegible (cifrado) para evitar que terceros no autorizados los comprendan. Esto se aplica a datos en tránsito (cuando se mueven a través de una red, por ejemplo, HTTPS/TLS) y datos en reposo (cuando están almacenados en bases de datos, discos duros, etc.
2.  `Políticas de privacidad y NDA (Acuerdos de No Divulgación) `: Documentos legales y políticas organizacionales que rigen el manejo y la divulgación de información sensible.
   
<a id="integridad"></a>
#### Integridad
La integridad se refiere a la garantía de que **la información es precisa, completa y confiable a lo largo de todo su ciclo de vida, y que no ha sido alterada de manera no autorizada o accidental**. En otras palabras, asegura que los datos no han sido modificados por agentes no autorizados y que **cualquier modificación autorizada es registrada y trazable**.

> Medidas para garantizar la integridad

1. `Firmas digitales`: Combinan el hashing con el cifrado de clave pública para verificar la autenticidad e integridad de un mensaje o documento. Si la firma es válida, se sabe que el documento no ha sido alterado desde que fue firmado.
2. `Controles de versiones y backups`: Mantener versiones anteriores de los datos y realizar copias de seguridad periódicas **permite restaurar los datos a un estado anterior si se corrompen o modifican incorrectamente**.
3. `Registros de auditoría (logs)`: Mantener registros detallados de todas las actividades y cambios en el sistema, incluyendo quién hizo qué, cuándo y dónde. Esto es fundamental para la trazabilidad y la detección de anomalías.

<a id="disponibilidad"></a>
#### Disponibilidad
La disponibilidad se refiere a la **garantía de que los sistemas, aplicaciones y datos sean accesibles y funcionales para los usuarios autorizados cuando sea necesario**. En otras palabras, asegura que los recursos de la información estén operativos y disponibles para su uso continuo y sin interrupciones.

> Medidas para garantizar la Disponibilidad
1.  `Redundancia y tolerancia a fallos `: Duplicar componentes críticos del sistema (servidores, bases de datos, enlaces de red, fuentes de alimentación) para que si uno falla, otro pueda tomar el relevo sin interrupción. Esto incluye balanceo de carga y clústeres de servidores.
2.  `Escalabilidad`: Diseñar sistemas que puedan manejar un aumento en la carga de usuarios o datos, ya sea mediante escalado vertical (más recursos a una sola máquina) u horizontal (añadir más máquinas)

<a id="owasp-top-10"></a>
### Vulnerabilidades comunes (OWASP Top 10)
El OWASP Top 10 es un informe estándar de concientización para desarrolladores y seguridad de aplicaciones web. Representa un consenso de las vulnerabilidades de seguridad más críticas que enfrentan las aplicaciones web y es una guía invaluable para cualquier persona involucrada en el diseño, desarrollo o despliegue de aplicaciones web seguras.

<a id="injection"></a>
#### Inyección (SQL Injection, Command Injection)
La vulnerabilidad de inyección ocurre cuando datos no confiables son enviados a un intérprete como parte de un comando o consulta. Los **datos maliciosos del atacante pueden engañar al intérprete para que ejecute comandos no deseados o acceda a datos sin la autorización adecuada**. 

La inyección puede ocurrir en varias formas, dependiendo del tipo de intérprete que se esté explotando. Las más comunes son SQL Injection y Command Injection.

> SQL Injection
Ocurre cuando un atacante inserta, o "inyecta", código SQL malicioso en una consulta a la base de datos a través de los campos de entrada de una aplicación. Si la aplicación no sanitiza o parametriza adecuadamente las entradas del usuario, este código inyectado puede ser interpretado y ejecutado por la base de datos.

- Ejemplo
  
Imaginemos una aplicación web que utiliza una consulta SQL para autenticar a un usuario, como: 
  * ```SELECT * FROM users WHERE username = '{$username}' AND password = '{$password}';```

Si un atacante introduce en el campo de username: ' OR '1'='1 y un valor cualquiera en password, la consulta resultante sería:
  * ```SELECT * FROM users WHERE username = '' OR '1'='1' AND password = 'cualquier_cosa';```

- La condición '1'='1' siempre es verdadera, lo que significa que la base de datos autenticará al atacante sin necesidad de una contraseña válida

Consecuencias:

1. `Evadir la autenticación`: Acceder a la aplicación como cualquier usuario, incluyendo administradores.
2. `Acceso no autorizado a datos`: Leer, modificar o eliminar datos de la base de datos, incluyendo información sensible de otros usuarios.
3. `Elevación de privilegios`: Si la cuenta de la base de datos tiene permisos suficientes, un atacante podría incluso crear o modificar tablas, funciones o incluso ejecutar comandos en el sistema operativo subyacente.

<a id="broken-autentication"></a>
#### Broken authentication
La vulnerabilidad de Broken authentication (a veces "Identificación y Autenticación Fallidas") se refiere a la **implementación incorrecta o incompleta de funciones relacionadas con la gestión de sesiones y la autenticación de usuarios**. Esto puede permitir a los atacantes comprometer contraseñas, claves o tokens de sesión, o explotar otras fallas de implementación para asumir la identidad de otros usuarios temporal o permanentemente.

> Ejemplos de fallas

1. `Credenciales débiles o por defecto`: Aplicaciones que permiten contraseñas muy simples (ej. "123456", "password") o que vienen con credenciales de administrador por defecto que no se cambian.
2. `Fuerza bruta y ataques de diccionario`: Ausencia de mecanismos para prevenir ataques automatizados que intentan adivinar contraseñas (ej. bloqueo de cuentas después de varios intentos fallidos, CAPTCHA).
3. `Manejo de sesiones inseguro`:
  * `IDs de sesión predecibles`: Generación de IDs de sesión que son fáciles de adivinar.
  * `Falta de invalidación de sesión`: La sesión del usuario no se invalida después del logout, cambio de contraseña o tiempo de inactividad. Esto puede permitir que un atacante reuse una sesión robada.
  * `No usar HttpOnly y Secure flags para cookies`: Las cookies de sesión sin el flag HttpOnly son accesibles por JavaScript, lo que las hace vulnerables a XSS. Las cookies sin el flag Secure se envían sobre HTTP no cifrado, exponiéndolas a la intercepción.

Consecuencias:

1. `Suplantación de identidad`: Un atacante puede hacerse pasar por un usuario legítimo.
2. `Acceso no autorizado`: Acceder a funciones o datos protegidos.
3. `Compromiso de cuenta`: Tomar el control completo de una cuenta de usuario.

<a id="sensitive-data-exposure"></a>
#### Sensitive data exposure
La vulnerabilidad de Sensitive Data Exposure ocurre cuando las aplicaciones web no protegen adecuadamente los datos sensibles. Esto incluye información financiera, de salud, PII (Información Personal Identificable), credenciales y otra información propietaria. Si estos datos no están protegidos apropiadamente, pueden ser robados o modificados por atacantes.

> Ejemplos de exposición

1. `No cifrar datos en tránsito`: Transmitir datos sensibles (credenciales, números de tarjetas de crédito) sobre conexiones no cifradas (HTTP en lugar de HTTPS).
2. `No cifrar datos en reposo`: Almacenar datos sensibles en bases de datos o sistemas de archivos sin cifrado adecuado. Por ejemplo, guardar números de tarjetas de crédito sin cifrar.
3. `Algoritmos de cifrado débiles o deprecados`: Usar algoritmos de cifrado débiles, algoritmos con implementaciones defectuosas, o claves de cifrado débiles/reutilizadas.
4. `Exposición de datos sensibles en mensajes de error o logs`: Mensajes de error detallados o archivos de log que contienen información sensible (números de tarjetas de crédito, detalles de errores de bases de datos, stack traces).
5. `Fugas de información en metadatos o archivos ocultos`: Archivos de respaldo, archivos de configuración (ej. .git, .env) o metadatos en imágenes que contienen información sensible.

Consecuencias:

1. `Robo de identidad`: Uso de PII para cometer fraude.
2. `Fraude financiero`: Uso de información de tarjetas de crédito o cuentas bancarias.
3. `Espionaje corporativo`: Robo de secretos comerciales o información estratégica.
4. `Daño a la reputación`: Pérdida de confianza de los clientes y socios.
5. `Multas regulatorias`: Incumplimiento de normativas de privacidad (GDPR, HIPAA, CCPA).

<a id="broken-access-control"></a>
#### Broken access control

<a id="cross-site-scripting"></a>
#### Cross-Site scripting (XSS)

<a id="cross-site-reques-forgery"></a>
#### Cross-Site request forgery (XSRF)

<a id="insecure-deserialization"></a>
#### Insecure deserialization

<a id="criptografia-basica"></a>
### Criptografía básica

<a id="cifrado-simetrico-y-asimetrico"></a>
#### Cifrado simétrico y asímetrico

<a id="Hashing"></a>
### Hashing

<a id="md5"></a>
#### MD5

<a id="bcrypt"></a>
#### BCrypt

<a id="sha-256"></a>
#### SHA-256
