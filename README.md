# Spring Security l

## Tabla de Contenido

- [Fundamentos de seguridad en aplicaciones web](#fundamentos-de-seguridad-en-aplicaciones)
  - [Autenticación vs. Autorización](#autenticacion-vs-autorizacion)
  - [Principios de seguridad (Acrónimo CIA)](#principios-de-seguridad)
    - [Confidencialidad](#confidencialidad)
    - [Integridad](#integridad)
    - [Disponibilidad](#disponibilidad)
  - [Vulnerabilidades comunes (OWASP Top 10)](#owasp-top-10)
    - [Inyección (Ej. SQL Injection)](#injection)
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
    - [SHA-256](#sha-256)
    - [BCrypt](#bcrypt)
- [Fundamentos de Spring Security](#fundamentos-de-spring-security)
    - [Arquitectura de Spring Security](#arquitectura-de-spring-security)
    - [FilterChainProxy y la cadena de filtros (Servlet Filters)](#filterchain-proxy-y-servlet-filters)
      - [BasicAuthenticationFilter](#basic-authentication-filter)
      - [UsernamePasswordAuthenticationFilter](#username-password-authentication-filter)
      - [Otros filtros comúnes](#otros-filtros)
      - [Orden de los filtros](#orden-de-los-filtros)
    - [SecurityContextHolder](#security-context-holder)
      - [Contexto por ThreadLocal](#contexto-por-thread-local)
      - [Contexto por HttpSession](#contexto-por-http-session)
    - [Las interfaces Authentication y GrantedAuthority](#interfaz-authenticacion-y-granted-authority)
    - [La interfaz UserDetailsService y UserDetails](#userdetails-service)
      - [Implementación y configuración](#implementacion-de-userdatails)
    - [AuthenticationManager y AuthenticationProvider](#auhtentication-manager-y-provider)
      - [DaoAuthenticationProvider](#dao-authentication-provider)
      - [Múltiples proveedores de autenticación](#multiples-proveedores-de-authenticacion)
    - [AccessDecisionManager y AccessDecisionVoter](#access-decision-manager-y-decision-voter)
      - [Estrategias de votación](#estrategias-de-votacion)
        - [AffirmativeBased](#affirmative-based)
        - [ConsensusBased](#consensus-based)
        - [UnanimousBased](#unanimous-based)
- [Configuración de Spring Security](#configuracion-de-spring-security)
    - [Configuración basada en Java](#configuracion-basada-en-java)
      - [La anotación @EnableWebSecurity](#la-anotacion-enable-web-security)
    - [Configuración para autorización](#configuracion-para-autorizacion)
      - [Autorización basada en URL](#autorizacion-basada-en-url)
        - [Los métodos .antMatchers(), .mvcMatchers(), .requestMatchers()](#los-metodos-para-autorizacion-por-url)
      - [Expresiones de seguridad](#expresiones-de-seguridad)
        - [Las expresiones hasRole(), hasAuthority(), isAuthenticated(), isAnonymous(), isFullyAuthenticated(), permitAll(), denyAll()](#expresiones-de-seguridad-para-autorizacion)
      - [Autorización basada en métodos](#autorizacion-basada-en-metodos)
        - [Las anotaciones @PreAuthorize, @PostAuthorize, @Secured](#anotaciones-para-autorizacion)
    - [CSRF Protection (Cross-Site Request Forgery)](#crsf-protection)
        - [Implementación por defecto](#implementacion-contra-crsf-por-defecto)
        - [Manejo en APIs REST](#manejo-de-crsf-en-apis)
    - [Session Management](#session-management)
      - [Estrategias de creación de sesión](#creacion-de-sesiones)
        - [Las estrategias always, if_required, never, stateless](#estrategias-para-la-creacion-de-sesiones)
      - [Control de concurrencia de sesiones](#concurrencia-de-sesiones)
      - [Invalidación de sesiones](#invalidacion-de-sesiones)
      - [Protección contra fijación de sesión](#proteccion-contra-fijacion-de-sesion)
    - [CORS (Cross-Origin Resource Sharing)](#cors)
      - [Configuración dentro de Spring Security](#configuracion-de-cors)

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
La vulnerabilidad de Broken Access Control (Control de Acceso Defectuoso) **ocurre cuando las restricciones sobre lo que los usuarios autenticados pueden hacer no se aplican correctamente**. Esto permite a los atacantes **eludir la autorización y acceder a funcionalidades o datos a los que no deberían tener acceso**, como cuentas de otros usuarios, archivos sensibles, o funcionalidades administrativas.

> Ejemplos de fallas

1. `Omisión de controles de acceso`: La aplicación no verifica si el usuario está autorizado para acceder a una URL o recurso específico. Por ejemplo, un usuario cambia user_id=123 en una URL por user_id=456 para ver los datos de otro usuario.
2. `Elevación de privilegios horizontal`: Un usuario puede acceder a recursos de otro usuario del mismo nivel de privilegio.
3. `Elevación de privilegios vertical`: Un usuario puede acceder a recursos o funciones de un usuario con un nivel de privilegio superior (ej. un usuario normal accede a funciones de administrador).
4. `Configuración incorrecta de CORS (Cross-Origin Resource Sharing)`: Permitir solicitudes de orígenes no confiables, lo que puede permitir que sitios maliciosos realicen solicitudes autorizadas en nombre del usuario.

Consecuencias:

* `Acceso no autorizado a datos`: Lectura, modificación o eliminación de datos de otros usuarios o datos sensibles del sistema.
* `Manipulación de la lógica de negocio`: Realizar acciones que solo deberían ser permitidas para ciertos roles.
  
<a id="cross-site-scripting"></a>
#### Cross-Site scripting (XSS)
Es una vulnerabilidad de inyección que **permite a los atacantes ejecutar scripts maliciosos (generalmente JavaScript) en el navegador de un usuario legítimo**. 

> Tipos de XSS

1. `XSS Reflejado (Reflected XSS)`: El payload malicioso se "refleja" directamente desde la entrada del usuario en la respuesta HTTP de la aplicación web. El atacante debe engañar al usuario para que haga clic en un enlace malicioso que contenga el script.

- Ejemplo: Un sitio de búsqueda vulnerable que refleja la entrada del usuario. Si un atacante envía un enlace como ```https://sitio.com/buscar?q=<script>alert('XSS');</script>```, y el sitio simplemente imprime ```Estás buscando: <script>alert('XSS');</script>```, el navegador del usuario ejecutará el script.

2. `XSS Almacenado/Persistente (Stored XSS)`: El payload malicioso se almacena de forma persistente en el servidor de la aplicación (ej. en una base de datos, en un foro, en un perfil de usuario, en comentarios). *Cada vez que un usuario accede a la página o función donde está almacenado el payload, el script se ejecuta en su navegador**. Este es el tipo más peligroso de XSS.
   
- Ejemplo: Un atacante publica un comentario en un blog que contiene un script malicioso. Cada usuario que vea ese comentario ejecutará el script.
  
3. `XSS Basado en DOM (DOM-based XSS)`: La vulnerabilidad reside en el código JavaScript del lado del cliente que procesa datos de una fuente no confiable (ej. URL, localStorage) y los escribe directamente en el DOM (Document Object Model) sin escape adecuado. El servidor no está involucrado en la inyección.


- Ejemplo: document.getElementById('name').innerHTML = location.hash.substring(1); si el hash contiene un script.
  
Consecuencias de XSS:

- `Robo de cookies de sesión`: El atacante puede robar la cookie de sesión del usuario y suplantar su identidad.
- `Redirección del usuario`: Redirigir al usuario a sitios de phishing.
- `Defacing de la we`b: Modificar el contenido de la página web que el usuario ve.
- `Ejecución de acciones en nombre del usuario`: Realizar acciones (cambiar contraseñas, enviar mensajes) en nombre del usuario sin su conocimiento.
- `Keylogging`: Registrar las pulsaciones de teclas del usuario.


<a id="cross-site-reques-forgery"></a>
#### Cross-Site request forgery (XSRF)
Es un ataque que **engaña a un navegador web para que envíe una solicitud HTTP no deseada a una aplicación web en la que el usuario ya está autenticado**. Si un usuario está autenticado en un sitio (ej. un banco en línea) y visita un sitio malicioso diseñado por un atacante, el sitio malicioso puede forzar al navegador del usuario a enviar una solicitud (ej. transferir dinero, cambiar contraseña) al sitio legítimo. El sitio legítimo **ve la solicitud como válida porque viene del navegador del usuario autenticado y contiene sus cookies de sesión**.

En otras palabras, explota la confianza del sitio web en el navegador del usuario y la forma en que los navegadores envían automáticamente las cookies.

> ¿Cómo funciona?

1. `Sesión activa`: Un usuario inicia sesión en bancolegitimo.com y tiene una sesión activa (cookie de sesión).
2. `Visita sitio malicioso`: El usuario, en otra pestaña o ventana, visita un sitio malicioso (ej. sitio-malicioso.com).
3. `Solicitud forjada`: El sitio malicioso contiene código (ej. una etiqueta <img> oculta, un formulario con auto-envío) que envía una solicitud HTTP a bancolegitimo.com en nombre del usuario.
  * Ejemplo de imagen oculta: ```<img src="https://bancolegitimo.com/transferencia?monto=1000&destino=atacante" style="display:none;">```
  * Ejemplo de formulario auto-enviado:    
```
<form action="https://bancolegitimo.com/cambiar_email" method="POST" id="csrfForm">
    <input type="hidden" name="email" value="email_del_atacante@malicious.com">
    <input type="hidden" name="password_confirm" value="contraseña_actual_del_usuario_que_no_se">
</form>
<script>document.getElementById('csrfForm').submit();</script>
```
4. `Ejecución de la solicitud`: El navegador del usuario, al cargar la imagen o enviar el formulario, incluye automáticamente las cookies de sesión de bancolegitimo.com (porque la solicitud va a ese dominio). El banco legítimo recibe la solicitud, la considera válida (ya que proviene de un usuario autenticado) y la ejecuta.

Consecuencias:

- Transferencias de dinero/transacciones no autorizadas.
- Manipulación de configuraciones de la cuenta.
- Cualquier acción que el usuario autenticado pueda realizar.

<a id="insecure-deserialization"></a>
#### Insecure deserialization
La deserialización es el proceso de convertir un flujo de bytes (un objeto serializado) en un objeto de datos en la memoria. Si un atacante puede manipular estos datos serializados, puede inyectar código o alterar la lógica de la aplicación cuando el objeto es deserializado.

Esto es especialmente peligroso en lenguajes que permiten la deserialización de objetos complejos (ej. Java, PHP, Python, Ruby, .NET) donde los objetos deserializados pueden contener métodos mágicos o callbacks que se ejecutan automáticamente durante la deserialización.

> Ejemplos de ataques

1. `Ejecución de código remoto (RCE)`: El atacante inyecta una clase o cadena que, al deserializarse, invoca funciones del sistema operativo o clases que permiten la ejecución de código.
2. `Denegación de servicio`: Deserializar una carga útil especialmente grande o recursiva puede agotar los recursos del sistema.
3. `Inyección de objetos`: Crear o modificar objetos en la aplicación que alteren su comportamiento de forma maliciosa.

<a id="criptografia-basica"></a>
### Criptografía básica
La criptografía se ha utilizado principalmente para la confidencialidad, transformando el texto plano (legible) en texto cifrado (ilegible) y viceversa. Sin embargo, en la era digital, su alcance se ha expandido enormemente para abordar una gama más amplia de desafíos de seguridad.

> Conceptos clave en criptografía

- `Texto Plano (Plaintext)`: La información original o mensaje legible antes de ser cifrado.
- `Texto Cifrado (Ciphertext)`: El mensaje transformado e ilegible después de la aplicación de un algoritmo de cifrado.
- `Cifrado (Encryption)`: El proceso de convertir texto plano en texto cifrado utilizando un algoritmo y una clave.
- `Descifrado (Decryption)`: El proceso de convertir texto cifrado de nuevo en texto plano utilizando un algoritmo y una clave.
- `Algoritmo Criptográfico (Cipher)`: Una función matemática utilizada para cifrar y descifrar datos.
- `Clave Criptográfica (Key)`: Un valor secreto utilizado por el algoritmo para realizar el cifrado y descifrado. La seguridad de un sistema criptográfico a menudo depende de la secrecía y la longitud de la clave, no de la secrecía del algoritmo (Principio de Kerckhoffs)

<a id="cifrado-simetrico-y-asimetrico"></a>
#### Cifrado simétrico y asímetrico

> Cifrado simétrico
En el cifrado simétrico, **la misma clave se utiliza tanto para cifrar como para descifrar la información**. Esta clave debe ser secreta y compartida de forma segura entre el emisor y el receptor.

- ¿Cómo funciona?

* `Emisor`: Toma el texto plano, aplica un algoritmo de cifrado simétrico y la clave secreta compartida para producir el texto cifrado.
* `Receptor`: Recibe el texto cifrado, aplica el mismo algoritmo de descifrado y la misma clave secreta compartida para recuperar el texto plano.

> [!NOTE]
> - `AES (Advanced Encryption Standard)`: Es el estándar de cifrado simétrico en la actualidad. Opera con tamaños de clave de 128, 192 o 256 bits y es considerado muy seguro. Ampliamente utilizado en cifrado de discos (BitLocker, FileVault) y comunicaciones seguras (TLS/SSL).
>
> - Uno de los usos de cifrado simétrico dentro de las aplicaciones web es el cifrar datos en reposo (ej. en bases de datos).

> Cifrado asimétrico

En el cifrado asimétrico, se utiliza un par de claves matemáticamente relacionadas: una clave pública y una clave privada. Lo que se cifra con una clave solo puede descifrarse con la otra clave del par

- ¿Cómo funciona?

1. Para Confidencialidad (Envío Seguro de Mensajes):
  * `Receptor`: Genera un par de claves: una clave pública (que puede compartir libremente con cualquiera) y una clave privada (que mantiene secreta).
  * `Emisor`: Quiere enviar un mensaje confidencial al receptor. Utiliza la clave pública del receptor para cifrar el mensaje.
  * `Receptor`: Recibe el texto cifrado y utiliza su propia clave privada (y solo su clave privada) para descifrarlo.

Un atacante que intercepte el texto cifrado y tenga la clave pública no podrá descifrar el mensaje porque necesita la clave privada.

2 Para Autenticación y No Repudio (Firmas Digitales):
  * `Emisor`: Quiere probar su identidad y asegurar que el mensaje no ha sido alterado. Utiliza su propia clave privada para "firmar" digitalmente el mensaje (o un hash del mensaje).
  * `Receptor`: Recibe el mensaje y la firma digital. Utiliza la clave pública del emisor para verificar la firma. Si la verificación es exitosa, se confirma que el mensaje fue enviado por el emisor (autenticación) y que no ha sido alterado desde que fue firmado (integridad y no repudio).

> [!NOTE]
> 
> * `RSA (Rivest–Shamir–Adleman)`: El algoritmo de cifrado asimétrico más conocido y ampliamente utilizado para el intercambio de claves, firmas digitales y cifrado de pequeños bloques de datos. Se basa en la dificultad de factorizar números primos grandes.

Uso en aplicaciones web:
- TLS/SSL (HTTPS): Se utiliza cifrado asimétrico al inicio para establecer una conexión segura (intercambio de claves, autenticación del servidor mediante certificados digitales) y luego se negocia una clave simétrica para cifrar el resto de la comunicación, aprovechando la velocidad del cifrado simétrico.
- Firmas digitales: Para verificar la autenticidad de software, documentos, etc.
  
<a id="Hashing"></a>
### Hashing
El hashing (o función hash criptográfica) es un proceso que toma un dato de entrada (o 'mensaje') de cualquier tamaño y produce una cadena de caracteres alfanuméricos de tamaño fijo, conocida como valor hash, código hash, digest del mensaje o simplemente hash.

A diferencia del cifrado, el hashing es una función unidireccional; no hay forma práctica de "deshacer" un hash para recuperar el dato original. Es decir, no hay un proceso de "deshashing".

> Propiedades de una función Hash Criptográfica

1. `Unidireccionalidad (Pre-image Resistance)`: Es computacionalmente inviable reconstruir el mensaje original a partir de su hash.
2. `Determinista`: La misma entrada siempre debe producir el mismo hash.
3. `Resistencia a colisiones (Collision Resistance)`: Es computacionalmente inviable encontrar dos mensajes diferentes que produzcan el mismo hash

> Proposito

1. `Almacenamiento Seguro de Contraseñas`: En lugar de almacenar contraseñas en texto plano (lo cual es un riesgo enorme), se almacena el hash de las contraseñas. Cuando un usuario intenta iniciar sesión, la contraseña que introduce se hashea y se compara con el hash almacenado. Si coinciden, la contraseña es correcta.
2. `Verificación de Integridad de Datos `: Almacenar el hash de un archivo. Si el archivo es modificado, su nuevo hash no coincidirá con el original, indicando una alteración. Se utiliza para verificar la integridad de descargas de software o comunicaciones.

<a id="md5"></a>
#### MD5
MD5 es un algoritmo de hashing criptográfico que produce un valor hash de 128 bits (16 bytes), típicamente representado como un número hexadecimal de 32 caracteres. Fue ampliamente utilizado en el pasado para verificar la integridad de archivos (ej. descargas de software) y para el almacenamiento de contraseñas. Sin embargo, a principios de la década de 2000, se descubrieron debilidades significativas en su resistencia a colisiones

> Problemas de seguridad

1. `Colisiones`: La principal debilidad. Si dos archivos pueden tener el mismo hash MD5, un atacante podría crear un archivo malicioso con el mismo hash que uno legítimo, lo que comprometería la verificación de integridad. 
2. No apto para contraseñas: Debido a su velocidad y la posibilidad de colisiones, MD5 es extremadamente inadecuado para el almacenamiento de contraseñas.
  * `Ataques de diccionario y fuerza bruta`: La velocidad de cálculo de MD5 permite a los atacantes probar millones de contraseñas por segundo.
  * `Rainbow Tables`: Tablas precalculadas de hashes para contraseñas comunes, lo que permite "invertir" hashes de forma rápida.


<a id="sha-256"></a>
#### SHA-256
SHA-256 es parte de la familia de algoritmos SHA-2 (Secure Hash Algorithm 2), produce un valor hash de 256 bits (32 bytes), típicamente representado como un número hexadecimal de 64 caracteres.

> Propiedades y seguridad

1. `Resistencia a colisiones`: Hasta la fecha (2025), no se han encontrado ataques prácticos de colisión contra SHA-256. Se considera criptográficamente seguro para este propósito.
2. `Unidireccionalidad`: Es computacionalmente inviable revertir un hash SHA-256 para encontrar la entrada original.
3. `Efecto avalancha`: Un cambio mínimo en la entrada produce un hash completamente diferente.

> Usos comunes

1. `Certificados digitales TLS/SSL`: Los certificados que aseguran HTTPS utilizan SHA-256 (u otros SHA-2) para firmar los certificados.
2. `Blockchain y criptomonedas`: SHA-256 es el algoritmo de hashing central utilizado en Bitcoin para la "prueba de trabajo" (Proof of Work) y para crear direcciones de monedero.

<a id="bcrypt"></a>
#### BCrypt
BCrypt es una **función de hashing de contraseñas basada en el algoritmo de cifrado Blowfish**. Fue diseñada por Niels Provos y David Mazières en 1999 específicamente para el almacenamiento de contraseñas, abordando las deficiencias de los algoritmos de hashing de propósito general (como MD5 o SHA-256) para esta tarea

- ¿Por qué BCrypt es mejor para contraseñas que MD5 o SHA-256?
1. "Salting" Integrado: Un salt **es una cadena aleatoria y única** que se añade a la contraseña antes de hashearla. BCrypt genera automáticamente un salt único para cada contraseña. Este salt se almacena junto con el hash.
2. "Key Stretching" (Factor de Costo/Iteraciones): BCrypt está diseñado para ser lento de propósito. Permite configurar un "factor de costo" (o "rounds" o "iteraciones"). Este factor determina cuántas veces se aplica el algoritmo internamente

Con estos dos factores, Bcrypt permite que se mantenga seguro a lo largo del tiempo sin cambiar el algoritmo.

- ¿Cómo funciona BCrypt para contraseñas?

1. Cuando un usuario establece una contraseña:

> - El sistema genera un salt aleatorio y único.
> - Toma la contraseña del usuario y el salt.
> - Aplica el algoritmo BCrypt con un factor de costo predefinido (ej. 10-12 iteraciones).
> - Almacena el hash resultante, que incluye el salt y el factor de costo incrustados en su formato.

2. Cuando un usuario intenta iniciar sesión:

> - El sistema recupera el hash almacenado para ese usuario, que contiene el salt y el factor de costo usados.
> - Toma la contraseña introducida por el usuario y el salt recuperado.
> - Aplica el algoritmo BCrypt con el factor de costo incrustado.
> - Compara el nuevo hash generado con el hash almacenado. Si coinciden, la contraseña es correcta.

> [!IMPORTANT]
> Un hash BCrypt típico se ve así: `$2a$10$abcdefghijklmnopqrstuvwx.Yz01234567890123456789012`
> 
> - $2a (o $2b, $2y): Identifica la versión del algoritmo BCrypt.
> - $10: Es el factor de costo (2^10 = 1024 iteraciones). Este valor es ajustable.
> - $abcdefghijklmnopqrstuvwx.: Es el salt generado aleatoriamente.
> - Yz01234567890123456789012: Es el hash final de la contraseña.

<a id="fundamentos-de-spring-security"></a>
## Fundamentos de Spring Security
El objetivo principal de Spring Security es proteger la aplicación contra accesos no autorizados, garantizando que solo los usuarios correctos puedan acceder a los recursos adecuados.
Una de las grandes ventajas de Spring Security es su extensibilidad. Está diseñado para ser modular y permitirle al desarrollador el reemplazar o añadir componentes según las necesidades del negocio, desde la forma en que los usuarios se autentican hasta cómo se definen y aplican los permisos.

<a id="arquitectura-de-spring-security"></a>
### Arquitectura de Spring Security
La arquitectura de Spring Security se basa en el concepto de filtros de Servlet y un conjunto de interfaces y clases que trabajan en conjunto para proporcionar seguridad. El corazón de esta arquitectura es el *FilterChainProxy*, que actúa como el punto de entrada principal para todas las solicitudes de seguridad.

![image](https://github.com/user-attachments/assets/4c14c7c0-10b2-4b2a-be04-a6f0a1435622)

> Componentes clave de la arquitectura

- `SecurityContextHolder`: Un mecanismo para **almacenar los detalles del usuario actualmente autenticado** (el Authentication object). Por defecto, **utiliza un ThreadLocal para que el contexto de seguridad esté disponible para cualquier parte de la aplicación** dentro del mismo hilo de ejecución.
  
- `Authentication`: Una interfaz que representa los detalles de un usuario autenticado. Contiene el principal (el usuario en sí, a menudo un objeto UserDetails), las credentials (la contraseña o token) y las authorities (los roles o permisos del usuario).
  
- `AuthenticationManager`: La interfaz principal para la autenticación. **Es responsable de recibir un Authentication object (a menudo incompleto, solo con credenciales) e intentar autenticarlo**, devolviendo un Authentication completamente poblado si la autenticación es exitosa.
  
- `AuthenticationProvider`: Implementaciones de AuthenticationManager que saben cómo autenticar tipos específicos de Authentication. Por ejemplo, un DaoAuthenticationProvider autentica usuarios contra un UserDetailsService.
  
- `UserDetailsService`: Una interfaz utilizada para **cargar información específica del usuario** (nombre de usuario, contraseña codificada, roles) por un nombre de usuario. Es crucial para integrar fuentes de usuarios personalizadas (bases de datos, LDAP, etc.).
  
- `AccessDecisionManager`: La interfaz principal para la autorización. **Decide si un usuario tiene permiso para acceder a un recurso protegido**, basándose en el Authentication del usuario y los atributos de configuración del recurso.
  
- `AccessDecisionVoter`: **Implementaciones de AccessDecisionManager** que votan si se debe otorgar o denegar el acceso. Un AccessDecisionManager puede usar múltiples AccessDecisionVoter para tomar una decisión final.
  
- `GrantedAuthority`: Una interfaz que **representa una autoridad (un permiso o rol)** otorgada a un Authentication principal.

<a id="filterchain-proxy-y-servlet-filters"></a>
### FilterChainProxy y la cadena de filtros (Servlet Filters)

Spring Security construye su magia **sobre la API de Servlet Filters de Java EE**. En pocas palabras, un Servlet Filter es un objeto que **puede interceptar solicitudes antes de que lleguen al servlet de destino** y también interceptar respuestas antes de que sean enviadas al cliente.

El componente central aquí es el `FilterChainProxy`. Este es un Servlet Filter especial de Spring Security que **actúa como el orquestador principal**. Cuando una solicitud HTTP llega a la aplicación web:

1. La solicitud es interceptada por el FilterChainProxy.
2. El FilterChainProxy **no realiza la lógica de seguridad directamente**, sino que **delega la responsabilidad** a una cadena de filtros de Spring Security (también conocidos como `Security Filters`).
3. Determina qué cadena de filtros específicos debe aplicarse a la solicitud actual basándose en la URL de la solicitud y su verbo HTTP.
4. Luego, itera a través de los filtros en esa cadena, **invocando a cada uno de ellos en un orden predefinido**. Cada filtro en la cadena realiza una tarea de seguridad específica (como autenticación básica, autenticación de formularios, manejo de sesiones, etc.).
5. Si un filtro decide que la solicitud no está autorizada o autenticada, puede detener la ejecución de la cadena y redirigir al usuario o lanzar una excepción de seguridad.
6. Si todos los filtros permiten que la solicitud continúe, eventualmente llegará al servlet de destino (por ejemplo, un controlador de Spring MVC).


<a id="basic-authentication-filter"></a>
#### BasicAuthenticationFilter
Es uno de los filtros de autenticación más simples y comunes en Spring Security, utilizado para implementar la autenticación HTTP Basic.

> ¿Cómo funciona?

1. Cuando una solicitud llega al servidor, el BasicAuthenticationFilter **inspecciona el encabezado Authorization de la solicitud HTTP**.
2. Si el encabezado Authorization está presente y su valor comienza con "Basic ", el filtro **intenta extraer el nombre de usuario y la contraseña codificados en Base64**.
3. Estos datos se utilizan para **crear un objeto UsernamePasswordAuthenticationToken** (un tipo de `Authentication`).
4. Este token se pasa al `AuthenticationManager` configurado para su autenticación.
5. Si el AuthenticationManager autentica exitosamente el token, el filtro establece el `Authentication` autenticado en el `SecurityContextHolder` y la solicitud continúa.
6. Si la autenticación falla, el filtro puede enviar una respuesta `HTTP 401 Unauthorized` al cliente, a menudo con un encabezado `WWW-Authenticate` para indicar que se requiere autenticación.

<a id="username-password-authentication-filter"></a>
#### UsernamePasswordAuthenticationFilter
Es el filtro por defecto y más utilizado para la autenticación basada en **formularios** en Spring Security.

> ¿Cómo funciona?

1. Este filtro se configura para "escuchar" en una URL de inicio de sesión específica **(por defecto, /login)**.
2. Cuando una solicitud POST llega a esta URL (normalmente desde un formulario HTML de inicio de sesión), el UsernamePasswordAuthenticationFilter extrae el nombre de usuario y la contraseña de los parámetros de la solicitud.
3. Al igual que con BasicAuthenticationFilter, utiliza estos datos para crear un UsernamePasswordAuthenticationToken.
4. Este token se pasa al `AuthenticationManager` para su procesamiento.
5. Si la autenticación es exitosa, el filtro:
  * Almacena el objeto `Authentication` autenticado en el `SecurityContextHolder`.
  * Invoca a un `AuthenticationSuccessHandler` (por defecto, una redirección a la URL de éxito configurada, a menudo /).
6. Si la autenticación falla:
  * Invoca a un `AuthenticationFailureHandler` (por defecto, una redirección de vuelta a la página de inicio de sesión con un mensaje de error).

<a id="otros-filtros"></a>
#### Otros filtros comúnes

- `LogoutFilter`: Gestiona el cierre de sesión de un usuario. Invalida la sesión, **limpia el SecurityContextHolder** y redirige a una URL de cierre de sesión exitoso.

- `ExceptionTranslationFilter`: Captura excepciones relacionadas con la seguridad `(AuthenticationException y AccessDeniedException)` lanzadas por filtros posteriores en la cadena y **las traduce en respuestas HTTP apropiadas** (por ejemplo, redireccionar a la página de inicio de sesión o a una página de acceso denegado).

- `SessionManagementFilter`: Gestiona la sesión del usuario, incluyendo la prevención de ataques de fijación de sesión, la concurrencia de sesiones (cuántas sesiones puede tener un usuario simultáneamente) y la expiración de sesiones.

- `RememberMeFilter`: Permite que los usuarios permanezcan autenticados entre sesiones de navegador sin tener que volver a iniciar sesión. **Utiliza cookies persistentes para almacenar un token de "recordarme"**.

- `CsrfFilter`: Protege contra ataques de falsificación de solicitudes entre sitios (CSRF) al verificar un token CSRF en cada solicitud POST.

- `AnonymousAuthenticationFilter`: Si un usuario no ha sido autenticado explícitamente, este filtro **asigna un Authentication "anónimo" al SecurityContextHolder**. Esto es útil para permitir que **recursos públicos sean accesibles por "usuarios" no autenticados**, mientras se les sigue aplicando la lógica de autorización.

- `FilterSecurityInterceptor`: Este es el último filtro en la cadena de seguridad y es el responsable de la autorización. Intercepta la solicitud justo antes de que llegue al controlador y decide si el usuario autenticado tiene permiso para acceder al recurso basándose en las reglas de autorización configuradas (por ejemplo, @PreAuthorize, hasRole()).
  
<a id="orden-de-los-filtros"></a>
#### Orden de los filtros
El orden de los filtros en la cadena de FilterChainProxy es absolutamente crucial. Cada filtro tiene un propósito específico y depende del trabajo realizado por filtros anteriores. Un orden incorrecto puede llevar a fallas de seguridad o comportamientos inesperados.

1. Filtros de manejo de `seguridad de bajo nivel/excepciones`: Estos filtros suelen estar al principio para manejar problemas generales o excepciones.
- `CsrfFilter` (protege contra CSRF)
- `LogoutFilter` (maneja el cierre de sesión)
- `ExceptionTranslationFilter` (maneja excepciones de seguridad)

2. `Filtros de autenticación`: Estos son los que intentan establecer la identidad del usuario.
- `BasicAuthenticationFilter`
- `UsernamePasswordAuthenticationFilter`
- `RememberMeFilter`
- `AnonymousAuthenticationFilter`

3. `Filtros de sesión y gestión`
- SessionManagementFilter

4. `Filtros de autorización `: Estos son los últimos, ya que requieren que el usuario esté autenticado para tomar decisiones de autorización.
- `FilterSecurityInterceptor`

> [!IMPORTANT]
> La presencia de cada filtro depende de las características de seguridad que se hayan habilitado en la aplicación (por ejemplo, si no se usa "recordarme", el **RememberMeFilter no estará activo**).

<a id="security-context-holder"></a>
### SecurityContextHolder

El propósito principal del SecurityContextHolder es **almacenar los detalles del principal (usuario) que está actualmente autenticado e interactuando con la aplicación**. En otras palabras, es el lugar donde Spring Security **guarda "quién eres" para el hilo de ejecución actual**.

Por ejemplo, si se necesita saber el nombre de usuario actual en la capa de servicio para registrar quién realizó una acción, simplemente se puede acceder a ```SecurityContextHolder.getContext().getAuthentication().getName()```.

<a id="contexto-por-thread-local"></a>
#### Contexto por ThreadLocal
El mecanismo por defecto y más común para almacenar el SecurityContext en el SecurityContextHolder es a través de un ThreadLocal.

¿Qué es un ThreadLocal?

Un ThreadLocal es una clase en Java que proporciona un **almacenamiento de datos que es local para cada hilo de ejecución**. Esto significa que cada hilo tiene su propia copia de la variable ThreadLocal, y los cambios realizados por un hilo en su copia no afectan las copias de otros hilos.

> ¿Cómo aplica a Spring Security?

1. Cuando una solicitud HTTP llega a la aplicación, **un nuevo hilo de ejecución es típicamente asignado para manejar esa solicitud**.
2. Los filtros de Spring Security (como UsernamePasswordAuthenticationFilter o BasicAuthenticationFilter) realizan la autenticación.
3. Una vez que un usuario es autenticado exitosamente, Spring Security crea un objeto Authentication completamente poblado.
4. Este **objeto Authentication se envuelve en un SecurityContext y se almacena en el SecurityContextHolder** utilizando un ThreadLocal para el hilo actual.
5. Mientras ese hilo maneja la solicitud, **cualquier parte del código dentro de ese hilo puede acceder a SecurityContextHolder.getContext()** para obtener los detalles de autenticación.
6. Cuando la solicitud termina y el hilo se "libera", **el SecurityContext se limpia automáticamente del ThreadLocal** para evitar fugas de memoria y garantizar que el contexto de seguridad no persista para solicitudes futuras manejadas por el mismo hilo (lo cual es crucial en entornos de servidores de aplicaciones donde los hilos son reutilizados).

<a id="contexto-por-http-session"></a>
#### Contexto por HttpSession
Aunque el almacenamiento principal es por ThreadLocal para la duración de la solicitud, **el SecurityContext también se guarda automáticamente en la HttpSession** de Java EE.

> ¿Por qué es necesario guardar el contexto en la sesión HTTP?

**Las solicitudes HTTP son, por naturaleza, "sin estado" (stateless)**. Esto significa que el servidor no recuerda nada sobre las solicitudes anteriores de un cliente a menos que se implemente un mecanismo para mantener el estado.

<a id="interfaz-authenticacion-y-granted-authority"></a>
### Las interfaces Authentication y GrantedAuthority
Estas dos interfaces son el corazón de cómo Spring Security representa la identidad y los permisos de un usuario.

> La interfaz Authentication

Es la representación principal de un principal (usuario) autenticado (o intentando autenticarse) en Spring Security. **Contiene toda la información necesaria sobre el usuario y sus credenciales**.

- Los métodos clave de la interfaz Authentication incluyen:

1. `Object getPrincipal()`: Representa el usuario que ha iniciado sesión. **A menudo es un objeto UserDetails** (que veremos a continuación) o un String con el nombre de usuario.
2. `Object getCredentials()`: Representa las credenciales del usuario (por ejemplo, la contraseña). **Por razones de seguridad, es común que las credenciales se borren (se pongan a null)** después de que la autenticación sea exitosa para evitar que la información sensible persista en la memoria.
3. `Collection<? extends GrantedAuthority>` getAuthorities(): Una colección de los permisos o roles que el usuario tiene.
4. `boolean isAuthenticated()`: Indica si el principal ha sido autenticado. Una vez que la autenticación es exitosa, este valor es true.
5. `Object getDetails()`: Proporciona detalles adicionales sobre la autenticación (por ejemplo, la dirección IP del cliente, el identificador de la sesión).

> [!IMPORTANT]
> Cuando un usuario inicia sesión, el `AuthenticationManager` devuelve una implementación de Authentication que contiene todos estos detalles. **Esta Authentication es la que se almacena en el SecurityContextHolder**.


> La interfaz GrantedAuthority

**Representa una autoridad (un permiso o rol) que ha sido concedida a un principal (usuario) autenticado**.

- El único método clave es:

1. `String getAuthority()`: Devuelve el nombre de la autoridad (por ejemplo, "ROLE_ADMIN", "READ_PRIVILEGE", "DELETE_PRODUCT")

> Puntos importantes sobre GrantedAuthority:
>
> - `Roles vs. Permisos`: Aunque se usan indistintamente, es común que las GrantedAuthority representen tanto roles (**agrupaciones de permisos** como "ADMIN", "USER") como permisos individuales (acciones específicas como "CREATE_PRODUCT", "VIEW_REPORT"). 
> 
> - `Prefijo "ROLE_"`: Por convención, las autoridades que representan roles suelen llevar el prefijo ROLE_. Por ejemplo, si tienes un rol "ADMIN", el GrantedAuthority sería `new SimpleGrantedAuthority("ROLE_ADMIN")`. Esto es especialmente importante cuando se usan expresiones de seguridad como hasRole('ADMIN'), ya que **Spring Security automáticamente añade el prefijo "ROLE_" si no está presente en la expresión**. Si tu GrantedAuthority no tiene el prefijo ROLE_, entonces debes usar hasAuthority('ADMIN') en tus expresiones.
> 
> - `Inmutabilidad`: Las implementaciones de GrantedAuthority suelen ser inmutables, ya que representan permisos fijos. La implementación más común es `SimpleGrantedAuthority`.

<a id="userdetails-service"></a>
### La interfaz UserDetailsService y UserDetails

> Interfaz UserDetailsService

Es una estrategia crucial que **Spring Security utiliza para cargar los detalles de un usuario dado su nombre de usuario**. Es la capa de abstracción entre el framework de seguridad y la fuente real de los datos del usuario (una base de datos, un directorio LDAP, o un servicio REST).

- El único método clave es:

1. `UserDetails loadUserByUsername(String username) throws UsernameNotFoundException`: Este método **es llamado por un AuthenticationProvider (comúnmente DaoAuthenticationProvider) cuando se intenta autenticar a un usuario**. Su responsabilidad es encontrar al usuario por su username y devolver un objeto UserDetails que contenga toda la información necesaria (nombre de usuario, contraseña, estado de la cuenta, autoridades). Si el usuario no se encuentra, debe lanzar una UsernameNotFoundException.

> [!IMPORTANT]
> Uno mismo tiene que **implementar esta interfaz** para definir cómo la aplicación obtiene la información del usuario de la base de datos o cualquier otro sistema.

> Interfaz UserDetails 

Representa los detalles completos de un usuario principal. Es el objeto que el UserDetailsService devuelve y que **Spring Security utiliza para realizar la autenticación y, posteriormente, la autorización**.

- UserDetails es análogo al Principal de Java EE y encapsula información como:

1. `String getUsername()`: El username del usuario (debe de ser único).

2. `String getPassword()`: La contraseña codificada del usuario. La contraseña aquí debe estar codificada (hashed) utilizando un PasswordEncoder. **Spring Security no almacenará contraseñas en texto plano por razones de seguridad**.

3. `Collection<? extends GrantedAuthority> getAuthorities()`: Una colección de los roles y permisos del usuario (GrantedAuthority).

4. `boolean isAccountNonExpired()`: Indica si la cuenta del usuario no ha caducado.

5. `boolean isAccountNonLocked()`: Indica si la cuenta del usuario no está bloqueada.

6. `boolean isCredentialsNonExpired()`: Indica si las credenciales (contraseña) del usuario no han caducado.

7. `boolean isEnabled()`: Indica si el usuario está habilitado (activo).

> [!NOTE]
> Spring Security proporciona una implementación por defecto conveniente: `org.springframework.security.core.userdetails.User`

<a id="implementacion-de-userdatails"></a>
#### Implementación y configuración

```
@AllArgsConstructor
@Service
public class UserDetailsServiceImpl implements UserDetailsService{
    private final CredentialRepository credentialRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Credential credential = this.findUser(username);
            List<SimpleGrantedAuthority> autorityList = List.of(
                            new SimpleGrantedAuthority("ROLE_USER")
                    );
          
          return new User(
                  credential.getEmail(),
                  credential.getPassword(),
                  autorityList
            );
    }


    private Credential findUser(String email) throws UsernameNotFoundException {
        Credential credential = this.credentialRepository.getCredentialByEmail(email);

        if (credential == null) 
            throw new UsernameNotFoundException(CredentialConstants.USERNAME_OR_PASSWORD_INCORRECT);
        
        return credential;
    }
    
}
```

* Método importante:
  
1. `UserDetails loadUserByUsername(String username)`: Este es el método central y Spring Security lo llamará automáticamente cuando necesite los detalles de un usuario basándose en su nombre de usuario (en esté caso, el email).

- List<SimpleGrantedAuthority> autorityList = List.of(new SimpleGrantedAuthority("ROLE_USER"));: Aquí se definen los roles o permisos del usuario. En este ejemplo simplificado, a cada usuario se le asigna el rol ROLE_USER.

-  return new User(...): Finalmente, se crea y devuelve una instancia de `org.springframework.security.core.userdetails.User`. Esta es una implementación por defecto de la interfaz UserDetails de Spring Security. Se le pasan tres argumentos clave:
  1. El nombre de usuario (email de la credencial).
  2. La contraseña codificada de la credencial.
  3. La lista de autoridades (roles/permisos) del usuario.

```
@AllArgsConstructor
@Service
public class AuthServiceImpl implements IAuthService{

    private final UserDetailsServiceImpl userDetailsServiceImpl;    
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;

    @Override
    public MessageResponse signIn(SignInRequest signInRequest) throws BadCredentialsException {
        Authentication authentication = this.authenticate(signInRequest.getEmail(), signInRequest.getPassword());
        SecurityContextHolder.getContext().setAuthentication(authentication);

        String accessToken = jwtUtil.generateToken(authentication);
        return new MessageResponse(accessToken);
    }

    public Authentication authenticate(String username, String password) throws BadCredentialsException {
        UserDetails userDetails = this.userDetailsServiceImpl.loadUserByUsername(username);
        if (!passwordEncoder.matches(password, userDetails.getPassword()))
            throw new BadCredentialsException(CredentialConstants.USERNAME_OR_PASSWORD_INCORRECT);

        return new UsernamePasswordAuthenticationToken(username, userDetails.getPassword(), userDetails.getAuthorities());
    }

}
```

En resumen, el flujo de autenticación es el siguiente:

1. Un usuario intenta iniciar sesión proporcionando un email y una contraseña hacía el `AuthServiceImpl`.

2. El `AuthServiceImpl` pide al `UserDetailsServiceImpl` que cargue los detalles del usuario asociados a ese email desde el `CredentialRepository`.

3. Una vez que se obtienen los detalles del usuario (UserDetails), el `AuthServiceImpl` utiliza el `BCryptPasswordEncoder` para verificar si la contraseña proporcionada por el usuario coincide con la contraseña codificada almacenada.

4. Si las credenciales son válidas, el AuthServiceImpl crea un objeto `Authentication` y lo establece en el `SecurityContextHolder`, marcando al usuario como autenticado para el resto de la solicitud.

5. Finalmente, se genera un JWT, que puede ser utilizado para mantener la sesión del usuario en futuras solicitudes sin necesidad de volver a enviar las credenciales.
   
```
@Configuration
public class PasswordEncoderConfig {
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
```

> [!NOTE]
> Es importante hacer la configuración del `Password Encoder` dentro de la aplicación, estó para asegurarse de hacer un hashing sobre las contraseñas de los ususarios antes de su resguardo en una base de datos.

<a id="auhtentication-manager-y-provider"></a>
### AuthenticationManager y AuthenticationProvider
En el proceso de autenticación dentro de Spring Security, encontramos dos interfaces clave que trabajan de la mano: AuthenticationManager y AuthenticationProvider. Juntos, orquestan el proceso de verificar la identidad de un usuario.

> AuthenticationManager

El AuthenticationManager **es la interfaz principal para la autenticación en Spring Security**. Su responsabilidad es simple pero crucial: recibir una solicitud de autenticación (representada por un objeto **Authentication**, que inicialmente solo contiene las credenciales del usuario) y, si es exitosa, devolver un objeto **Authentication** completamente poblado que representa un usuario autenticado. **Si la autenticación falla, lanzará una excepción**.

> [!NOTE]
> El AuthenticationManager delega la tarea real de autenticación. No sabe cómo autenticar a un usuario por sí mismo; en su lugar, delega esta tarea a uno o más `AuthenticationProviders`.

- El método clave es:

1. `Authentication authenticate(Authentication authentication) throws AuthenticationException`: Este método es invocado por los filtros de autenticación (como UsernamePasswordAuthenticationFilter o BasicAuthenticationFilter) cuando necesitan autenticar a un usuario. Recibe un objeto Authentication (por ejemplo, un UsernamePasswordAuthenticationToken con nombre de usuario y contraseña) y, si la autenticación es exitosa, devuelve un Authentication completamente poblado (con principal, credentials limpias y authorities).

> AuthenticationProvider

Los AuthenticationProviders son los "trabajadores" reales que **saben cómo realizar un tipo específico de autenticación*. Cada AuthenticationProvider está diseñado para autenticar un tipo particular de credenciales o de fuente de usuario.

- Los métodos clave de la interfaz AuthenticationProvider son:

1. `Authentication authenticate(Authentication authentication) throws AuthenticationException`: Este es el método donde se implementa la lógica de autenticación real.
2. `boolean supports(Class<?> authentication)`: Este método es utilizado por el AuthenticationManager para **determinar qué AuthenticationProvider puede manejar un tipo específico de objeto Authentication**. Por ejemplo, un DaoAuthenticationProvider indicará que soporta UsernamePasswordAuthenticationToken.

Cuando un AuthenticationManager recibe una solicitud de autenticación, **itera sobre la lista de AuthenticationProviders configurados**. Para cada AuthenticationProvider, llama a su método supports(). Si un AuthenticationProvider indica que puede manejar el tipo de Authentication dado, entonces el AuthenticationManager invoca su método authenticate() para intentar la autenticacióN.

<a id="dao-authentication-provider"></a>
#### DaoAuthenticationProvider
El `DaoAuthenticationProvider` es la implementación más común y utilizada de AuthenticationProvider en aplicaciones que **autentican usuarios contra una base de datos**.

> ¿Cómo funciona?

1. El `DaoAuthenticationProvider` se configura con una instancia de UserDetailsService y un PasswordEncoder.

2. Cuando el DaoAuthenticationProvider recibe un objeto Authentication (**típicamente un UsernamePasswordAuthenticationToken**), extrae el nombre de usuario de este token.

3. Llama al método loadUserByUsername() de su UserDetailsService configurado, pasándole el nombre de usuario. El UserDetailsService es responsable de cargar los detalles del usuario (un objeto UserDetails) de la fuente de datos subyacente.

4. Una vez que obtiene el UserDetails, el DaoAuthenticationProvider compara la contraseña proporcionada en el Authentication original (que el usuario envió) con la contraseña codificada del UserDetails, utilizando el PasswordEncoder configurado.

6. Si las contraseñas coinciden, y la cuenta del usuario (UserDetails) está habilitada, no bloqueada y no expirada, entonces la autenticación es exitosa. El DaoAuthenticationProvider construye y devuelve un nuevo objeto Authentication completamente poblado (con el UserDetails como principal y las GrantedAuthoritys asociadas).
   
7. Si la autenticación falla por cualquier motivo (usuario no encontrado, contraseña incorrecta, cuenta bloqueada, etc.), se lanza una AuthenticationException.

<a id="multiples-proveedores-de-authenticacion"></a>
#### Múltiples proveedores de autenticación
Spring Security permite configurar múltiples AuthenticationProviders con un único AuthenticationManager. Esto es extremadamente útil en escenarios donde necesitas autenticar usuarios contra diferentes fuentes o usando diferentes mecanismos

> ¿Cómo funciona con múltiples proveedores?

Cuando el AuthenticationManager (específicamente la implementación ProviderManager que Spring Security usa por defecto) recibe un objeto Authentication para autenticar:

1. Itera a través de su lista configurada de AuthenticationProviders.
2. Para cada AuthenticationProvider, llama a su método supports(Class<?> authentication) para verificar si ese proveedor es capaz de manejar el tipo de Authentication que se está intentando autenticar.
3. Si un proveedor supports() el tipo de autenticación, el ProviderManager invoca su método authenticate().
4. Si un proveedor autentica exitosamente la solicitud, el ProviderManager devuelve inmediatamente el Authentication autenticado y detiene la iteración.
5. Si todos los proveedores que supports() el tipo de autenticación fallan (lanzan una AuthenticationException), o si ningún proveedor supports() el tipo de autenticación, el ProviderManager lanzará su propia AuthenticationException

> Ejemplo
```
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class MultiAuthProviderConfig {

    private final UserDetailsService myUserDetailsService;
    private final MyLdapUserDetailsService myLdapUserDetailsService; // Asume que tienes otro UserDetailsService para LDAP

    public MultiAuthProviderConfig(UserDetailsService myUserDetailsService, MyLdapUserDetailsService myLdapUserDetailsService) {
        this.myUserDetailsService = myUserDetailsService;
        this.myLdapUserDetailsService = myLdapUserDetailsService;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationProvider daoAuthenticationProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(myUserDetailsService); // UserDetailsService para usuarios de DB
        provider.setPasswordEncoder(passwordEncoder());
        return provider;
    }

    @Bean
    public AuthenticationProvider ldapAuthenticationProvider() {
        // Ejemplo de un AuthenticationProvider para LDAP
        // Esto sería una implementación real de LdapAuthenticationProvider
        // Simplificado para el ejemplo
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider(); // Podría ser LdapAuthenticationProvider real
        provider.setUserDetailsService(myLdapUserDetailsService); // UserDetailsService para usuarios LDAP
        provider.setPasswordEncoder(passwordEncoder()); // LDAP puede tener su propio codificador o no
        return provider;
    }

    // Configurando los AuthenticationProviders directamente en HttpSecurity
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(authorize -> authorize
                .anyRequest().authenticated()
            )
            .formLogin(form -> form.permitAll())
            .authenticationProvider(daoAuthenticationProvider()) // Primero intenta autenticar con DB
            .authenticationProvider(ldapAuthenticationProvider()); // Luego intenta autenticar con LDAP

        return http.build();
    }
}
```

En este ejemplo, Spring Security primero intentará autenticar con el daoAuthenticationProvider. Si falla, luego intentará con el ldapAuthenticationProvider.

<a id="access-decision-manager-y-decision-voter"></a>
### AccessDecisionManager y AccessDecisionVoter
Una vez que un usuario ha sido autenticado (es decir, sabemos "quién eres"), el siguiente paso es la autorización (es decir, "¿qué puedes hacer?"). 

Aquí es donde entran en juego el `AccessDecisionManager` y los `AccessDecisionVoters`. Ellos determinan si un principal (usuario) autenticado tiene el derecho de acceder a un recurso protegido o de ejecutar una acción específica.

> AccessDecisionManager

El AccessDecisionManager es la interfaz principal para la toma de decisiones de autorización. Similar al **AuthenticationManager**, no toma las decisiones de autorización por sí mismo. En su lugar, **delega la "votación" a una colección de `AccessDecisionVoters`**.

El método clave es:

1. `void decide(Authentication authentication, Object object, Collection<ConfigAttribute> configAttributes) throws AccessDeniedException`: Este método es invocado por el FilterSecurityInterceptor (el último filtro en la cadena de seguridad).

Recibe:
- `authentication`: El objeto Authentication del usuario actualmente autenticado.
- `object`: El objeto de seguridad protegido que el usuario intenta acceder (por ejemplo, la URL de la solicitud, un método que se va a invocar).
- `configAttributes`: Una colección de atributos de configuración asociados con el objeto protegido (por ejemplo, ROLE_ADMIN, hasRole('USER')). Estos son los requisitos de seguridad que deben cumplirse para acceder al recurso.

Basándose en las "votaciones" de los AccessDecisionVoters, el AccessDecisionManager toma una decisión final:
* Si el acceso es concedido, el método simplemente regresa y la ejecución continúa.
* Si el acceso es denegado, lanza una AccessDeniedException.


> AccessDecisionVoters

Son implementaciones de la interfaz que "votan" sobre si un principal autenticado debería tener acceso a un recurso protegido. Cada AccessDecisionVoter puede especializarse en evaluar un tipo particular de atributo de configuración o de lógica de autorización.

- Los métodos clave son:
  
1. `int vote(Authentication authentication, Object object, Collection<ConfigAttribute> configAttributes)`: Este es el método central donde el votante emite su voto.

Puede devolver uno de tres valores:

* `ACCESS_GRANTED (1)`: El votante concede el acceso.
* `ACCESS_DENIED (-1)`: El votante deniega el acceso.
* `ACCESS_ABSTAIN (0)`: El votante no puede tomar una decisión (por ejemplo, no entiende los configAttributes dados o no tiene suficiente información)

2. `boolean supports(ConfigAttribute attribute)`: Indica si este votante es capaz de procesar un tipo específico de ConfigAttribute

<a id="estrategias-de-votacion"></a>
#### Estrategias de votación
La forma en que el `AccessDecisionManager` interpreta los votos de los `AccessDecisionVoters` se conoce como estrategia de votación. Spring Security proporciona varias implementaciones de AccessDecisionManager, cada una con una estrategia de votación diferente.

<a id="affirmative-based"></a>
##### AffirmativeBased
Esta es la estrategia por defecto. **Si al menos un AccessDecisionVoter concede ACCESS_GRANTED, el acceso es inmediatamente concedido**, independientemente de los votos ACCESS_DENIED de otros votantes. **Si ningún votante concede el acceso, y al menos uno deniega (ACCESS_DENIED), entonces el acceso es denegado**. Si todos los votantes se abstienen (ACCESS_ABSTAIN), el acceso es denegado por defecto.

> Ejemplo
>
> * Si un recurso requiere ROLE_ADMIN o ROLE_EDITOR, y el usuario tiene ROLE_ADMIN, se concederá el acceso incluso si un votante niega el acceso por no tener ROLE_EDITOR.

<a id="consensus-based"></a>
##### ConsensusBased
El AccessDecisionManager cuenta los votos ACCESS_GRANTED y ACCESS_DENIED. **Si el número de votos ACCESS_GRANTED es mayor que el número de votos ACCESS_DENIED, el acceso es concedido**. Si los votos ACCESS_DENIED son mayores, el acceso es denegado. 

Si hay un empate, o todos se abstienen, la decisión se basa en la configuración de `allowIfEqualGrantedDeniedDecisions` y `allowIfAllAbstainDecisions`.

> [!NOTE]
> Útil cuando se desea que múltiples factores contribuyan a la decisión de acceso, y una simple mayoría determina el resultado.
>
> - Ejemplo: Un recurso requiere tanto ROLE_USER como IP_WHITELISTED. Un votante concede por ROLE_USER, otro votante deniega por IP_NOT_WHITELISTED. Si hay más votos de denegación, el acceso es denegado.


<a id="unanimous-based"></a>
##### UnanimousBased

Para que el acceso sea concedido, **todos los AccessDecisionVoters que no se abstengan (ACCESS_ABSTAIN) deben votar ACCESS_GRANTED**. Si un solo votante emite un voto ACCESS_DENIED, el acceso es denegado. Si todos los votantes se abstienen, el acceso es denegado por defecto.

> [!NOTE]
> Útil cuando la seguridad es extremadamente estricta y se requiere que absolutamente todas las condiciones de seguridad se cumplan para conceder acceso
> 
> - Ejemplo: Un recurso requiere ambos ROLE_DEVELOPER y que el acceso sea desde una VPN_CORPORATIVA. Si un votante verifica el rol y lo concede, pero otro votante verifica la VPN y la deniega, el acceso general será denegado.


<a id="configuracion-de-spring-security"></a>
## Configuración de Spring Security
Desde **Spring Security 3.2**, la configuración basada en Java se ha convertido en la forma preferida y más idiomática de configurar la seguridad en tus aplicaciones. Permite una mayor flexibilidad, legibilidad y reutilización de código en comparación con la configuración basada en XML

<a id="configuracion-basada-en-java"></a>
### Configuración basada en Java
La configuración basada en Java se basa en definir beans de configuración que extienden o usan la funcionalidad de Spring Security.

<a id="la-anotacion-enable-web-security"></a>
#### La anotación @EnableWebSecurity
***Esta anotación es el punto de partida para la configuración de seguridad basada en Java en Spring MVC**. Cuando se coloca sobre una clase de configuración (una clase anotada con @Configuration), **le indica a Spring que debe importar las configuraciones de Spring Security y habilitar sus características de seguridad**. 

> [!IMPOTANT]
>
> Internamente, `@EnableWebSecurity` importa la clase `WebSecurityConfiguration`, que es la que realmente configura el filtro de Spring Security `(FilterChainProxy)` para la aplicación web/API REST.

- Ejemplo
```
@Configuration
@EnableWebSecurity
public class SecurityConfig {

}
```

<a id="configuracion-para-autorizacion"></a>
### Configuración para autorización
La autorización es el proceso de determinar si un usuario autenticado tiene permiso para acceder a un recurso o realizar una acción específica. En Spring Security, la autorización se puede configurar a nivel de URL (o ruta) y también a nivel de método.

<a id="autorizacion-basada-en-url"></a>
#### Autorización basada en URL
La autorización basada en URL es la forma más común de controlar el acceso a diferentes recursos. Permite especificar qué roles o autoridades se requieren para acceder a ciertas rutas basándose en las reglas de autorización.

<a id="los-metodos-para-autorizacion-por-url"></a>
##### Los métodos .antMatchers(), .mvcMatchers(), .requestMatchers()
Estos métodos son fundamentales para definir patrones de URL y aplicarles reglas de seguridad. Se utilizan dentro de la configuración de Spring Security, típicamente dentro del método `configure(HttpSecurity http)`.

1. `http.antMatchers()`: Es el más antiguo y utiliza patrones de estilo Ant. Un patrón Ant puede incluir:
  * `?`: coincide con un carácter único.
  * `*`: coincide con cero o más caracteres dentro de un segmento de ruta.
  * `**`: coincide con cero o más segmentos de ruta.

- Ejemplo
```
http.antMatchers("/admin/**").hasRole("ADMIN") // Todas las URLs bajo /admin/
http.antMatchers("/user/*").hasAnyRole("USER", "ADMIN") // URLs como /user/profile, pero no /user/profile/edit
```

2. `http.mvcMatchers()`: Introducido en Spring Framework 4.1 y Spring Security 4.0, es más inteligente que `antMatchers()` porque **entiende los patrones de URL definidos por Spring MVC** (como `@RequestMapping`). Es más preciso y robusto, ya que utiliza el HandlerMapping de Spring MVC para la coincidencia.

- Ejemplo
```
http.mvcMatchers("/products/{id}").permitAll() // Coincide exactamente con la forma en que MVC mapea 
```  

3. `http.requestMatchers()`: Es la forma recomendada en versiones más recientes de Spring Security. Permite usar PathRequest para recursos estáticos (CSS, JS, imágenes), patrones Ant (AntPathRequestMatcher) o patrones de Spring MVC (MvcRequestMatcher).
```
http.requestMatchers("/public/**").permitAll();
http.requestMatchers(PathRequest.toStaticResources().atCommonLocations()).permitAll(); // Para recursos estáticos
http.requestMathcers(HttpMethod.POST, "/api/v1/register").permitAll();
```

> [!IMPORTANT]
> Spring Security procesa las reglas en el orden en que las declaras. Por lo tanto, las reglas más específicas deben ir antes que las más generales.

<a id="expresiones-de-seguridad"></a>
#### Expresiones de seguridad
Las expresiones de seguridad son un lenguaje potente y flexible que Spring Security utiliza para definir reglas de autorización. Permiten construir condiciones complejas basadas en el rol del usuario, sus autoridades, si está autenticado, etc.

<a id="expresiones-de-seguridad-para-autorizacion"></a>
##### Las expresiones hasRole(), hasAuthority(), isAuthenticated(), isAnonymous(), isFullyAuthenticated(), permitAll(), denyAll()

1. `hasRole(String role)`: Retorna `true` si el usuario autenticado tiene el **rol* especificado. Por convención, Spring Security automáticamente añade el prefijo `"ROLE_"` a los roles cuando se usa hasRole(). Por ejemplo, hasRole("ADMIN") busca la autoridad `"ROLE_ADMIN"`.

- Ejemplo
```
http.requestMatchers(HttpMethod.GET, CommonConstants.PRIVATE_URL + "/**").hasRole("ADMIN");
```

2. `hasAuthority(String authority)`: Retorna `true` si el usuario autenticado tiene la autoridad **(permiso)** específica. A diferencia de hasRole(), hasAuthority() no añade ningún prefijo. Es más flexible y se usa cuando necesitas un control más granular que los roles simples.

- Ejemplo
```
http.requestMatchers(HttpMehthod.DELETE, "/api/product/delete").hasAuthority("DELETE_PRODUCT_PERMISSION")
```

3. `isAuthenticated()`: Retorna `true` si el usuario actual ha sido autenticado, incluso si ha sido por "recordarme" (remember-me) o autenticación anónima (si está habilitada).

- Ejemplo
```
http.requestMatchers(HttpMethod.GET, "/dashboard").isAuthenticated()
```

4. `isAnonymous()`: Retorna `true` si el usuario actual es un usuario anónimo (no ha iniciado sesión).

- Ejemplo
```
http.requestMatchers(HttpMethod.POST, "/login").isAnonymous()
```

5. `isFullyAuthenticated()`: Retorna true si el usuario actual ha sido autenticado completamente (no a través de "recordarme" o anónimo). Esto es útil para acciones de alta seguridad donde se quiere asegurar que el usuario haya ingresado sus credenciales recientemente.

- Ejemplo
```
http.requestMatchers(HttpMethod.PATCH, "/settings/change-password").isFullyAuthenticated()
```

6. `permitAll()`: Permite el acceso a cualquier usuario, sin importar si está autenticado o qué roles/autoridades tiene.

- Ejemplo
```
http.requestMatchers(HttpMethod.POST, "/login").permitAll()
```

7. `denyAll()`: Deniega el acceso a todos los usuarios, incluso si están autenticados y tienen los roles correctos. Es útil para deshabilitar temporalmente ciertas partes de la aplicación.

- Ejemplo
```
.antMatchers("/maintenance").denyAll()
```

<a id="autorizacion-basada-en-metodos"></a>
#### Autorización basada en métodos
Mientras que la autorización basada en URL controla el acceso a rutas completas dentro de una aplicación/API REST, la autorización basada en métodos te **permite aplicar reglas de seguridad a métodos individuales dentro de tus clases de servicio o controladores**. Esto es increíblemente útil cuando **diferentes usuarios pueden acceder a la misma URL, pero solo algunos tienen permiso para ejecutar ciertas operaciones o acceder a datos específicos devueltos por un método**.

Para habilitar la seguridad basada en anotaciones en tus métodos, necesitas añadir `@EnableMethodSecurity`:
```
@Configuration
@EnableWebSecurity
@EnableMethodSecurity 
public class SecurityConfig {
    // ... 
}
```

<a id="anotaciones-para-autorizacion"></a>
##### Las anotaciones @PreAuthorize, @PostAuthorize, @Secured

> @PreAuthorize

PreAuthorize **se evalúa antes de que el método anotado se ejecute**. Utiliza expresiones de seguridad de `Spring Expression Language (SpEL)`, por lo que permite crear condiciones de autorización muy complejas.

- Ejemplos:
  
1. Verificar roles:
```
  @PreAuthorize("hasRole('ADMIN')")
  public String deleteUser(Long userId) { ... }
```

2. Verificar autoridades:
```
@PreAuthorize("hasAuthority('USER_DELETE_PERMISSION')")
public String deleteUser(Long userId) { ... }
```

3. Combinar roles y autoridades:
```
@PreAuthorize("hasAnyRole('ADMIN', 'MANAGER') or hasAuthority('CREATE_REPORT')")
public Report generateReport(ReportCriteria criteria) { ... }
```

4. Acceder a parámetros del método:
```
@PreAuthorize("#userId == authentication.principal.id")
public UserProfile getUserProfile(Long userId) {
    // Solo el usuario con el ID especificado puede acceder a este perfil
    ...
}
```

> @PostAuthorize

PostAuthorize se evalúa después de que el método anotado se ha ejecutado y **tiene acceso al valor de retorno del método**. 
¿Cuándo utilizarlo? Cuando la decisión de autorización depende del resultado de la operación del método. Por ejemplo, para asegurarse de que un usuario solo pueda ver documentos si es el propietario, una vez que el documento ha sido recuperado de la base de datos.

- Ejemplo:
```
@PostAuthorize("returnObject.ownerId == authentication.principal.id")
public Document getDocumentById(Long documentId) {
    Document doc = documentService.findById(documentId);
    return doc; // La expresión se evalúa sobre este 'doc'
}
```
> [!IMPORTANT]
> El uso de `@PostAuthorize` puede ser delicado porque el método ya se ejecutó. Si la autorización falla, es posible que ya se haya realizado alguna acción (como una eliminación), aunque Spring Security arrojará una excepción `AccessDeniedException`.


> @Secured

Esta es una anotación más simple y la forma original de realizar autorización basada en métodos en Spring Security. **Solo permite especificar una lista de roles (o autoridades) que se requieren para acceder al método**.

- Ejemplos
```
@Secured("ROLE_ADMIN") // Requiere el prefijo "ROLE_" explícitamente por defecto
public void deleteProduct(Long productId) { ... }

@Secured({"ROLE_USER", "ROLE_ADMIN"})
public List<Order> getUserOrders(Long userId) { ... }
```

- No soporta expresiones SpEL

<a id="crsf-protection"></a>
### CSRF Protection (Cross-Site Request Forgery)

<a id="implementacion-contra-crsf-por-defecto"></a>
#### Implementación por defecto

<a id="manejo-de-crsf-en-apis"></a>
#### Manejo en APIs REST

<a id="session-management"></a>
### Session Management

<a id="creacion-de-sesiones"></a>
#### Estrategias de creación de sesión

<a id="estrategias-para-la-creacion-de-sesiones"></a>
##### Las estrategias always, if_required, never, stateless

<a id="concurrencia-de-sesiones"></a>
#### Control de concurrencia de sesiones

<a id="invalidacion-de-sesiones"></a>
#### Invalidación de sesiones

<a id="proteccion-contra-fijacion-de-sesion"></a>
#### Protección contra fijación de sesión

<a id="cors"></a>
### CORS (Cross-Origin Resource Sharing)

<a id="configuracion-de-cors"></a>
#### Configuración dentro de Spring Security





