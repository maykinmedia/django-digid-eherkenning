��    �        �   �	      H     I  [   X     �  /   �  �   �  L   �  @   !  "   b  
   �     �  �   �  !   O  =   q  7   �  !   �  $   	  4   .  �   c  �   �     �  U   �       &         G     b     �     �     �  �   �  	   z  �   �     }  .   �  G   �            0   +  _   \  N   �  &        2     ?  <   Z  6   �  �   �  	   m  3   w  5   �  /   �  7        I     Q     Z  =   k  f   �  9     <   J  :   �  7   �  F   �  �   A  M   �  V   $  O   {  v   �  &   B  F   i     �     �     �  3   �  &     0   -  ,   ^  :   �     �     �     �               )    E     N   �   \      �      !  �   !  C   �!  -   �!  Z   -"  3   �"  A   �"  b   �"  >   a#  �   �#  �   V$  o   %  f   }%  i   �%  `   N&  B   �&     �&  %   '     1'  $   C'  )   h'  A   �'     �'     �'     	(     (  	   &(  	   0(     :(     F(     S(     l(     x(     �(     �(     �(  -   �(     �(  !   �(     )  	    )  '   *)     R)     e)  	   �)  
   �)     �)     �)  #   �)     �)     �)     *     *     (*     :*     I*     _*     |*  %   �*     �*     �*     �*     �*     +     +     %+     9+     R+     r+  
   �+     �+     �+  `  �+      -  c   1-     �-  0   �-  �   �-  V   �.  O   /  +   o/  
   �/     �/  �   �/  !   �0  <   �0  7   �0  $   1  &   ?1  9   f1  �   �1  �   A2     3  P   13     �3  &   �3     �3     �3     �3     4     4  �   94  	   �4    �4     �5  1   6  W   L6     �6     �6  A   �6  }   7  S   7  0   �7     8      8  8   38  3   l8  �   �8     V9  =   s9  <   �9  7   �9  /   &:     V:     ^:     g:  1   x:  `   �:  =   ;  E   I;  E   �;  ?   �;  Y   <  �   o<  T   =  a   f=  V   �=     >  $   �>  N   �>     ?     $?     5?  ;   9?  &   u?  0   �?  ,   �?  :   �?     5@     J@     `@     t@     �@     �@     �@     �A  �   �A     B     �B  �   �B  D   KC  /   �C  V   �C  0   D  ;   HD  s   �D  >   �D  �   7E  �   �E  �   �F  �   0G  �   �G  ~   =H  I   �H     I     !I     >I     PI  +   pI  D   �I  &   �I     J  	   $J     .J     EJ  	   QJ     [J     gJ     tJ     �J     �J     �J     �J     �J  -   �J     K      2K     SK  	   YK  '   cK     �K     �K  	   �K  
   �K     �K     �K  #   L     (L     8L     KL     XL     hL     xL     �L  %   �L     �L  '   �L     M     M     (M     =M     VM     bM     nM  %   �M  (   �M  	   �M     �M     �M     �M         <   7      )   �   0          �   �   W       @          P   ^   �   j   	       p       Q   B   �             �          S   d       1   T   =      �   �   G   #                 c   ~   6   ,       2         5   E   i       �   n   V       �         �          ]   e   u       `   M   3       r             Z                      g   J   %   �   8           (           z         h       L   x   }   s   k       [   X   �   A       �   �       &   ;   >   K       �   
   C   |   H   4   w       v   /   �      t       b   U   {   '       �                a      �           R              Y       !   -      o   I   �   _       �   �   \   �       *   m   q      f       ?   �   �   �   "   O          �              �           D   �   l       :   $   9   F       �   .       N   +           �   y         (new account) 'application/soap+xml' is considered legacy and modern brokers typically expect 'text/xml'. (no certificate selected) A description of the service you are providing. A list of additional requested attributes. A single requested attribute can be a string (the name of the attribute) or an object with keys 'name' and 'required', where 'name' is a string and 'required' a boolean'. A list of strings (or objects) with the requested attributes, e.g. '["bsn"]' A technical error occurred from %(ip)s during %(service)s login. A valid OIN consists of 20 digits. Activation Advanced settings An error occurred in the communication with DigiD. Please try again later. If this error persists, please check the website https://www.digid.nl for the latest information. Attribute consuming service index Attribute consuming service index for the eHerkenning service Attribute consuming service index for the eIDAS service Attributes to extract from claims BSN should have %(size)i characters. Base URL of the application, without trailing slash. Certificate that may be used by the specified configuration. The best matching candidate will automatically be selected by the configuration. Claim that specifies how the legal subject claim must be interpreted. The expected claim value is one of: 'urn:etoegang:1.9:EntityConcernedID:KvKnr' or 'urn:etoegang:1.9:EntityConcernedID:RSIN'. Common settings Could not find any identity provider information in the metadata at the provided URL. DigiD DigiD & eHerkenning via OpenID Connect DigiD, eHerkenning & eIDAS DigiD/eHerkenning certificate DigiD/eHerkenning certificates Digid configuration Eherkenning/eIDAS configuration Email address of the technical person responsible for this DigiD/eHerkenning/eIDAS setup. For it to show up in the metadata, you should also specify the phone number. Endpoints Example value: 'https://was-preprod1.digid.nl/saml/idp/metadata'. Note that this must match the 'entityID' attribute on the 'md:EntityDescriptor' node found in the Identity Provider's metadata. This is auto populated from the configured source URL. Expected a numerical value. Failed to parse the metadata, got error: {err} Fallback level of assurance, in case no claim value could be extracted. High (4) Identity provider If True the XML assertions need to be encrypted. If True, the XML assertions need to be signed, otherwise the whole response needs to be signed. If True, then the service catalogue will contain only the eHerkenning service. If enabled, Single Logout is supported Invalid BSN. Keycloak specific settings Level of Assurance (LoA) to use for the eHerkenning service. Level of Assurance (LoA) to use for the eIDAS service. Level of assurance claim value mappings. Useful if the values in the LOA claim are proprietary, so you can translate them into their standardized identifiers. LoA claim Login failed due to no BSN being returned by DigiD. Login failed due to no BSN having more then 9 digits. Login failed due to no BSN not being numerical. Login to eHerkenning did not succeed. Please try again. Low (2) Low (2+) Manage ({count}) Metadata for eHerkenning/eidas will contain this language key Name of the claim holding the (opaque) identifier of the user representing the authenticated company.. Name of the claim holding the BSN of the authorized user. Name of the claim holding the BSN of the represented person. Name of the claim holding the BSN of the represented user. Name of the claim holding the authenticated user's BSN. Name of the claim holding the identifier of the authenticated company. Name of the claim holding the level of assurance. If left empty, it is assumed there is no LOA claim and the configured fallback value will be used. Name of the claim holding the service ID for which the company is authorized. Name of the claim holding the service UUID for which the acting subject is authorized. Name of the claim holding the service UUID for which the company is authorized. Name of the claim holding the value of the branch number for the authenticated company, if such a restriction applies. Name of the service you are providing. No RSIN returned by eHerkenning. Login to eHerkenning did not succeed. Non existent (1) Number value OIN OIN of the broker used to set up eHerkenning/eIDAS. OpenID Connect configuration for DigiD OpenID Connect configuration for DigiD Machtigen OpenID Connect configuration for eHerkenning OpenID Connect configuration for eHerkenning Bewindvoering OpenID Connect scope OpenID Connect scopes Organization details SAML configuration Service details Service provider entity ID. Signature algorithm. Note that DSA_SHA1 and RSA_SHA1 are deprecated, but RSA_SHA1 is still the default value in the SAMLv2 standard. Warning: there are known issues with single-logout functionality if using anything other than SHA1 due to some hardcoded algorithm. Single logout Something went wrong while generating the metadata. Please get in touch with your technical contact person and inform them the configuration is invalid. String value Substantial (3) Telephone number of the technical person responsible for this DigiD/eHerkenning/eIDAS setup. For it to show up in the metata, you should also specify the email address. The %(service)s login from %(ip)s did not succeed or was cancelled. The OIN of the company providing the service. The URL where the privacy policy from the organization providing the service can be found. The URL where the service description can be found. The URL-source where the XML metadata file can be retrieved from. The metadata file of the identity provider. This is auto populated from the configured source URL. This configuration and certificate combination already exists. URL of the organization providing the service for which DigiD/eHerkenning/eIDAS login is configured. For it to show up in the metadata, you should also specify the organization URL. URL of the organization providing the service for which DigiD/eHerkenning/eIDAS login is configured. For it to show up in the metadata, you should also specify the organization name. UUID of the eHerkenning service instance. Once entered into catalogues, changing the value is a manual process. UUID of the eHerkenning service. Once entered into catalogues, changing the value is a manual process. UUID of the eIDAS service instance. Once entered into catalogues, changing the value is a manual process. UUID of the eIDAS service. Once entered into catalogues, changing the value is a manual process. User %(user)s%(user_info)s from %(ip)s logged in using %(service)s View SAML metadata (XML) View service catalogue metadata (XML) X.509 Certificate You are not authenticated with Digid You have cancelled logging in with DigiD. You must prepare at least one certificate for the {verbose_name}. acting subject identifier claim authorizee bsn claim base URL branch number claim broker ID bsn claim certificate certificates company identifier claim config type default LOA digest algorithm eHerkenning eHerkenning LoA eHerkenning attribute consuming service index eHerkenning service UUID eHerkenning service instance UUID eIDAS eIDAS LoA eIDAS attribute consuming service index eIDAS service UUID eIDAS service instance UUID entity ID expires on identifier type claim identity provider metadata identity provider service entity ID loa mapping metadata file(XML) URL no eIDAS organization URL organization name privacy policy representee bsn claim representee identifier claim requested attributes resolve artifact binding content type service ID claim service UUID claim service description service description URL service language service name signature algorithm technical contact: email technical contact: phone number valid candidate? valid from want assertions encrypted want assertions signed Project-Id-Version: PACKAGE VERSION
Report-Msgid-Bugs-To: 
PO-Revision-Date: 2020-06-23 16:55+0200
Last-Translator: Sergei Maertens <sergei@maykinmedia.nl>
Language-Team: Maykin Media <info@maykinmedia.nl>
Language: NL
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8
Content-Transfer-Encoding: 8bit
Plural-Forms: nplurals=2; plural=(n != 1);
  (nieuw account) 'application/soap+xml' wordt als 'legacy' beschouwd. Moderne brokers verwachten typisch 'text/xml'. (geen certificaat geselecteerd) Een beschrijving van de service die je aanbiedt. Een lijst van extra gewenste attributen. Eén enkel gewenst attribuut kan een string (de naam van het attribuut) zijn of een object met de sleutels 'name' en 'required', waarbij 'name' een string is en 'required' een boolean. Een lijst van strings (of objecten) met de gewenste attributen, bijvoorbeeld '["bsn"]' Er is een technische fout opgetreden tijdens de %(service)s-login vanaf %(ip)s. Een geldig OIN moet uit 20 cijfers bestaan. Activering Geavanceeerde instellingen Er is een fout opgetreden in de communicatie met DigiD. Probeert u het later nogmaals. Indien deze fout blijft aanhouden, kijk dan op de website https://www.digid.nl voor de laatste informatie. Attribute consuming service index Attribute consuming service index voor de eHerkenningservice Attribute consuming service index voor de eIDAS-service Attributen om uit de claims te halen Een BSN bestaat uit %(size)i getallen. De basis-URL van de applicatie, zonder slash op het eind. Certificaat dat mogelijk gebruikt zal worden voor de geselecteerde configuratie. De best geschikte optie wordt automatisch geselecteerd op basis van geldigheid. Claim die aangeeft hoe de bedrijfsidentificatiewaarde dient geïnterpreteerd te worden. Verwachtte waarden voor deze claim zijn: 'urn:etoegang:1.9:EntityConcernedID:KvKnr' of 'urn:etoegang:1.9:EntityConcernedID:RSIN'. Algemene instellingen Kon geen identity provider-informatie vinden in de metadata op de opgegeven URL. DigiD DigiD & eHerkenning met OpenID Connect DigiD, eHerkenning & eIDAS DigiD/eHerkenning certificaat DigiD/eHerkenning certificaten DigiD-configuratie eHerkenning/eIDAS-configuratie E-mailadres van de technische contactpersoon voor deze DigiD/eHerkenning/eIDAS-installatie. Je moet ook het telefoonnummer opgeven voor dit in de metadata beschikbaar is. Endpoints Bijvoorbeeld: 'https://was-preprod1.digid.nl/saml/idp/metadata'. Merk op dat dit moet overeenkomen met het 'entityID'-attribuut op het 'md-EntityDescriptor'-element in de metadata van de identity provider. Dit wordt automatisch opgehaald via de ingestelde metadata-URL. De waarde moet numeriek zijn. Kon de metadata niet verwerken. De fout is: {err} Standaardwaarde voor het betrouwbaarheidsniveau, voor als er geen claim beschikbaar is. High (4) Identity provider Indien aangevinkt, dan moeten de XML-assertions versleuteld zijn. Indien aangevinkt, dan moeten de XML-assertions ondertekend zijn. In het andere geval moet de hele response ondertekend zijn. Indien aangevinkt, dan zal de dienstcatalogus enkel de eHerkenningservice bevatten. Single Logout is beschikbaar indien ingeschakeld Ongeldig BSN. Keycloak-specifieke instellingen Betrouwbaarheidsniveau (LoA) voor de eHerkenningservice. Betrouwbaarheidsniveau (LoA) voor de eIDAS-service. Waardevertalingen voor betrouwbaarheidsniveaus. Wanneer makelaars geen standaardwaarden aanleveren kan je deze alsnog vertalen naar de standaardwaarden uit de eHerkenning standaard. Betrouwbaarheidsniveau-claim Login mislukt doordat er geen BSN is teruggegeven door DigiD. Login mislukt doordat er geen BSN gevonden is met 9 cijfers. Login mislukt doordat er geen numeriek BSN gevonden is. eHerkenning-login mislukt. Probeer het nogmaals Low (2) Low (2+) Beheer ({count}) eHerkenning/eIDAS-metadata zal deze taal bevatten Naam van de claim die de (versleutelde) medewerkeridentificatie van het ingelogde bedrijf bevat. Naam van de claim die het BSN bevat van de vertegenwoordiger. Naam van de claim die het BSN bevat van de vertegenwoordigde persoon. Naam van de claim die het BSN bevat van de vertegenwoordigde persoon. Naam van de claim die het BSN bevat van de ingelogde gebruiker. Naam van de claim die de identificatie van het ingelogde/vertegenwoordigde bedrijf bevat. Naam van de claim die het betrouwbaarheidsniveau bevat. Indien je deze leeg laat, dan wordt aangenomen dat er geen claim is en wordt de standaardwaarde gebruikt. Naam van de claim die het ID van de dienst bevat waarvoor het bedrijf gemachtigd is. Naam van de claim die het (UU)ID van de dienst bevat waarvoor de vertegenwoordiger gemachtigd is. Naam van de claim die het UUID van de dienst bevat waarvoor het bedrijf gemachtigd is. Naam van de claim die het vestigingsnummer van het ingelogde bedrijf bevat, wanneer een dergelijke beperking van toepassing is. Naam van de service die je aanbiedt. eHerkenning gaf geen RSIN terug. Het inloggen moet eHerkenning is niet gelukt. Non existent (1) Numerieke waarde OIN OIN van de makelaar waarmee eHerkenning/eIDAS ingericht is. OpenID Connect-configuratie voor DigiD OpenID Connect-configuratie voor DigiD Machtigen OpenID Connect-configuratie voor eHerkenning OpenID Connect-configuratie voor eHerkenning Bewindvoering OpenID Connect scope OpenID Connect scopes Organisatiegegevens SAML-configuratie Servicegegevens Service provider entity ID. Ondertekenalgoritme. Merk op dat DSA_SHA1 en RSA_SHA1 deprecated zijn, maar RSA_SHA1 is nog steeds de default-waarde ind e SAMLv2-standaard. Opgelet: er zijn bekende problemen met de single-logoutfunctionaliteit indien je een ander algoritme dan SHA1 gebruikt (door hardcoded algoritmes). Single logout Er ging iets fout bij het genereren van de metadata. Neem a.u.b. contact op met uw technisch contactpersoon en informeer hen dat de configuratie ongeldig is. Tekstuele waarde Substantial (3) Telefoonnummer van de technische contactpersoon voor deze DigiD/eHerkenning/eIDAS-installatie. Je moet ook het e-mailadres opgeven voor dit in de metadata beschikbaar is. De %(service)s-login van %(ip)s is niet geslaagd of was geannuleerd. De OIN van het bedrijf dat de service aanbiedt. De URL waar het privacybeleid van de service-aanbieder (organisatie) beschreven staat. De URL waar de omschrijving van de dienst staat. De URL waar het XML metadata-bestand kan gedownload worden. Het bestand met metadata van de identity provider. Deze wordt automatisch opgehaald via de ingestelde metadata-URL. Dit certificaat bestaat al voor de geselecteerde configuratie. Naam van de organisatie die de service aanbiedt waarvoor DigiD/eHerkenning/eIDAS-authenticatie ingericht is. Je moet ook de URL opgeven voor dit in de metadata beschikbaar is. URL van de organisatie die de service aanbiedt waarvoor DigiD/eHerkenning/eIDAS-authenticatie ingericht is. Je moet ook de organisatienaam opgeven voor dit in de metadata beschikbaar is. UUID van de eHerkenningservice-instantie. Eenmaal dit in catalogi opgenomen is kan de waarde enkel via een handmatig proces gewijzigd worden. UUID van de eHerkenningservice. Eenmaal dit in catalogi opgenomen is kan de waarde enkel via een handmatig proces gewijzigd worden. UUID van de eIDAS-service-instantie. Eenmaal dit in catalogi opgenomen is kan de waarde enkel via een handmatig proces gewijzigd worden. UUID van de eIDAS-service. Eenmaal dit in catalogi opgenomen is kan de waarde enkel via een handmatig proces gewijzigd worden. Gebruiker %(user)s%(user_info)s is met %(service)s ingelogd vanaf %(ip)s. SAML metadata inzien (XML) Dienstcatalogus inzien (XML) X.509 Certificaat U bent niet ingelogd met DigiD. U heeft het inloggen met DigiD geannuleerd. Je moet minstens één certificaat instellen voor de {verbose_name}. identificatie handelende persoon-claim BSN vertegenwoordiger-claim Basis-URL vestigingsnummer-claim makelaar-ID BSN-claim certificaat certificaten bedrijfsidenticatie-claim configuratietype standaardbetrouwbaarheidsniveau digest algorithm eHerkenning eHerkenning LoA eHerkenning attribute consuming service index UUID eHerkenningservice UUID eHerkenningservice instance eIDAS eIDAS LoA eIDAS attribute consuming service index UUID eIDAS-service UUID eIDAS-service instance entity ID vervalt op soort identificatie-claim metadata identity provider identity provider service entity ID LoA-vertalingen (XML) metadata-URL zonder eIDAS organisatie-URL organisatienaam privacybeleid BSN vertegenwoordigde-claim identificatie vertegenwoordigde-claim gewenste attributen Content-Type 'resolve artifact binding' service ID-claim service UUID-claim Service-omschrijving Service-omschrijving URL servicetaal servicenaam signature algorithm technisch contactpersoon: e-mailadres technisch contactpersoon: telefoonnummer geschikt? geldig vanaf versleutel assertions onderteken assertions 