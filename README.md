# Spring Security

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
    - [La interfaz UserDetailsService y la clase UserDetails](#userdetails-service)
      - [Implementación y configuración](#implementacion-de-userdatails)
    - [AuthenticationManager y AuthenticationProvider](#auhtentication-manager-y-provider)
      - [DaoAuthenticationProvider](#dao-authentication-provider)
      - [Múltiples proveedores de autenticación](#multiples-proveedores-de-authenticacion)
    - [AccessDecisionManager y AccessDecisionVoter](#access-decision-manager-y-decision-voter)
      - [Estrategias de votación](#estrategias-de-votacion)
        - [AffirmativeBased](#affirmative-based)
        - [ConsensusBased](#consensus-based)
        - [UnanimousBased](#unanimous-based)
          
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
BCrypt es una *función de hashing de contraseñas basada en el algoritmo de cifrado Blowfish**. Fue diseñada por Niels Provos y David Mazières en 1999 específicamente para el almacenamiento de contraseñas, abordando las deficiencias de los algoritmos de hashing de propósito general (como MD5 o SHA-256) para esta tarea

- ¿Por qué BCrypt es mejor para contraseñas que MD5 o SHA-256?
1. "Salting" Integrado: Un salt **es una cadena aleatoria y única** que se añade a la contraseña antes de hashearla. BCrypt genera automáticamente un salt único para cada contraseña. Este salt se almacena junto con el hash.
2. "Key Stretching" (Factor de Costo/Iteraciones): BCrypt está diseñado para ser lento de propósito. Permite configurar un "factor de costo" (o "rounds" o "iteraciones"). Este factor determina cuántas veces se aplica el algoritmo internamente

Con estos dos factores, Bcrypt permite que se mantenga seguro a lo largo del tiempo sin cambiar el algoritmo.


- ¿Cómo funciona BCrypt para contraseñas?

> 1. Cuando un usuario establece una contraseña:
>
> - El sistema genera un salt aleatorio y único.
> - Toma la contraseña del usuario y el salt.
> - Aplica el algoritmo BCrypt con un factor de costo predefinido (ej. 10-12 iteraciones).
> - Almacena el hash resultante, que incluye el salt y el factor de costo incrustados en su formato.

> 2. Cuando un usuario intenta iniciar sesión:
>
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

<a id="arquitectura-de-spring-security"></a>
### Arquitectura de Spring Security

<a id="filterchain-proxy-y-servlet-filters"></a>
### FilterChainProxy y la cadena de filtros (Servlet Filters)

<a id="basic-authentication-filter"></a>
#### BasicAuthenticationFilter

<a id="username-password-authentication-filter"></a>
#### UsernamePasswordAuthenticationFilter

<a id="otros-filtros"></a>
#### Otros filtros comúnes

<a id="orden-de-los-filtros"></a>
#### Orden de los filtros

<a id="security-context-holder"></a>
### SecurityContextHolder

<a id="contexto-por-thread-local"></a>
#### Contexto por ThreadLocal

<a id="contexto-por-http-session"></a>
#### Contexto por HttpSession

<a id="interfaz-authenticacion-y-granted-authority"></a>
### Las interfaces Authentication y GrantedAuthority

<a id="userdetails-service"></a>
### La interfaz UserDetailsService y la clase UserDetails

<a id="implementacion-de-userdatails"></a>
#### Implementación y configuración

<a id="auhtentication-manager-y-provider"></a>
### AuthenticationManager y AuthenticationProvider

<a id="dao-authentication-provider"></a>
#### DaoAuthenticationProvider

<a id="multiples-proveedores-de-authenticacion"></a>
#### Múltiples proveedores de autenticación

<a id="access-decision-manager-y-decision-voter"></a>
### AccessDecisionManager y AccessDecisionVoter

<a id="estrategias-de-votacion"></a>
#### Estrategias de votación

<a id="affirmative-based"></a>
##### AffirmativeBased

<a id="consensus-based"></a>
##### ConsensusBased

<a id="unanimous-based"></a>
##### UnanimousBased





