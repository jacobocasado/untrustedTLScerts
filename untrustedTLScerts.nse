local datetime = require "datetime"
local nmap = require "nmap"
local outlib = require "outlib"
local shortport = require "shortport"
local sslcert = require "sslcert"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local tls = require "tls"
local unicode = require "unicode"
local have_openssl, openssl = pcall(require, "openssl")

description = [[
Retrieves a server's x509 certificate and detects certificates which their
SubjectName is part of a list of suspicious names or IPs, or it is a self-signed certificate.

As enhanced functionality, we included:
- The result of looking for suspicious names in the SubjectAltName field as well.
- Output a warning if the validity period is less than 31 days or more than 1000 days.
- The result of looking for the fingerprint of the certificate (SHA1) in the .csv file (added as an extra column).
- Added an extra .csv file with malicious issuer information to do the same procedure above (SubjectName / CommonName) but with the issuer information.

Example:

<code>
443/tcp open  https
| untrustedTLScerts: 
| -----------------------------------
| Subject CommonName: www.paypal.com
| Subject organizationName:PayPal, Inc.
| Subject localityName:San Jose
| Subject countryName:US
| Subject Alternative Name: DNS:www.paypal.com, DNS:www.paypal.com.ar, DNS:www-st.paypal.com, DNS:m.paypal.es, DNS:www.paypal.com.au, DNS:id.hyperwallet.com, DNS:www.paypal.co, DNS:creditapply.paypal.com, DNS:www.paypal.ch, DNS:pp-us.paypal.com, DNS:safebreach.paypal.com, DNS:www.paypal.cl, DNS:demo.paypal.com, DNS:mobile.paypal.com, DNS:www.paypal.co.id, DNS:checkout.paypal.com, DNS:www.paypal.ca, DNS:sspserv.paypal.com, DNS:www.paypal.com.sa, DNS:brand.braintreepayments.com, DNS:www.braintreepayments.com, DNS:www.paypal.com.br, DNS:securepayments.paypal.com, DNS:www.paypal.com.sg, DNS:transfer.paypal.com, DNS:m.paypal.fr, DNS:www.paypal.co.za, DNS:www.paypal-france.fr, DNS:www.paypal.co.in, DNS:www.paypal.co.il, DNS:www.paypal.se, DNS:assets-cdn.sandbox.s-xoom.com, DNS:id.xoom.com, DNS:www.thepaypalblog.com, DNS:www.paypal.jp, DNS:assets-cdn.s-xoom.com, DNS:js.braintreegateway.com, DNS:www.paypal.be, DNS:www.paypal.com.cn, DNS:onboarding.paypal.com, DNS:www.paypal.vn, DNS:www.paypal.es, DNS:www.paypal.com.tr, DNS:www.paypal.eu, DNS:www.braintreefinancial.com, DNS:www.paypal.com.tw, DNS:assets.braintreegateway.com, DNS:braintreefinancial.com, DNS:www.brand.braintreepayments.com, DNS:py.pl, DNS:www.paypal-deutschland.de, DNS:www.paypal.me, DNS:id.venmo.com, DNS:www.paypal.co.kr, DNS:id.zettle.com, DNS:cors.api.paypal.com, DNS:www.paypal.dk, DNS:login.paypal.com, DNS:pp-au.paypal.com, DNS:www.paypal.lu, DNS:pp-eu.paypal.com, DNS:www.paypal.com.es, DNS:www.paypal.de, DNS:www.paypal.co.th, DNS:www.paypal.com.my, DNS:www.paypal.com.mx, DNS:secure.paypal.com, DNS:www.paypal.com.ve, DNS:www.paypal.ph, DNS:www.paypal-latam.com, DNS:braintreepayments.com, DNS:www.paypal-forward.com, DNS:www.py.pl, DNS:m.paypal.it, DNS:history.paypal.com, DNS:www.paypal.co.uk, DNS:braintreecharge.com, DNS:t.paypal.com, DNS:braintreepaymentsolutions.com, DNS:c6.paypal.com, DNS:m.paypal.com, DNS:pics.paypal.com, DNS:www.braintreecharge.com, DNS:www.paypal.fr, DNS:business.paypal.com, DNS:id.joinhoney.com, DNS:financing.paypal.com, DNS:ssp.paypal.com, DNS:www.braintreepaymentsolutions.com, DNS:id.paypal.com, DNS:developer.paypal.com, DNS:fpdbs.paypal.com, DNS:www.paypal-marketing.pl, DNS:www.paypal.nl, DNS:www.paypal.no, DNS:www.paypal.fi, DNS:www.paypalobjects.com, DNS:www.paypal-mena.com, DNS:www.paypal.co.nz, DNS:www.paypal.com.pe, DNS:qwac.paypal.com, DNS:content.paypalobjects.com, DNS:www.paypal.at, DNS:id.braintreegateway.com, DNS:paypal.me, DNS:www.paypal.in, DNS:pointofsale-s.paypal.com, DNS:p.paypal.com, DNS:www.paypal.it, DNS:www.paypal.com.hk, DNS:www.paypal.ie, DNS:zettleintegrations.paypal.com, DNS:pp-in.paypal.com, DNS:c.paypal.com, DNS:www.paypal-gifts.com, DNS:m.paypal.co.uk, DNS:pep.paypal.com, DNS:www.paypal.pt, DNS:m.paypal.com.au, DNS:www.paypal.pl
| -----------------------------------
| This certificate's commonName, organizationName or altName (v3) do not appear in the malicious blocklist.
| -----------------------------------
| Issuer CommonName: DigiCert SHA2 Extended Validation Server CA
| Issuer organizationName:DigiCert Inc
| This certificate is not self signed as both subject and issuers are not the same. 
| -----------------------------------
| Not valid before: 2022-11-10T00:00:00
| Not valid after:  2023-11-10T23:59:59
|_The validity of this certificate is 365 days.

</code>

]]

---
-- @see ssl-cert.nse
--
-- @output
-- 443/tcp open  https
-- | untrustedTLScerts: 
-- | -----------------------------------
-- | Subject CommonName: www.paypal.com
-- | Subject organizationName:PayPal, Inc.
-- | Subject localityName:San Jose
-- | Subject countryName:US
-- | Subject Alternative Name: DNS:www.paypal.com, DNS:www.paypal.com.ar, DNS:www-st.paypal.com, DNS:m.paypal.es, DNS:www.paypal.com.au, DNS:id.hyperwallet.com, DNS:www.paypal.co, DNS:creditapply.paypal.com, DNS:www.paypal.ch, DNS:pp-us.paypal.com, DNS:safebreach.paypal.com, DNS:www.paypal.cl, DNS:demo.paypal.com, DNS:mobile.paypal.com, DNS:www.paypal.co.id, DNS:checkout.paypal.com, DNS:www.paypal.ca, DNS:sspserv.paypal.com, DNS:www.paypal.com.sa, DNS:brand.braintreepayments.com, DNS:www.braintreepayments.com, DNS:www.paypal.com.br, DNS:securepayments.paypal.com, DNS:www.paypal.com.sg, DNS:transfer.paypal.com, DNS:m.paypal.fr, DNS:www.paypal.co.za, DNS:www.paypal-france.fr, DNS:www.paypal.co.in, DNS:www.paypal.co.il, DNS:www.paypal.se, DNS:assets-cdn.sandbox.s-xoom.com, DNS:id.xoom.com, DNS:www.thepaypalblog.com, DNS:www.paypal.jp, DNS:assets-cdn.s-xoom.com, DNS:js.braintreegateway.com, DNS:www.paypal.be, DNS:www.paypal.com.cn, DNS:onboarding.paypal.com, DNS:www.paypal.vn, DNS:www.paypal.es, DNS:www.paypal.com.tr, DNS:www.paypal.eu, DNS:www.braintreefinancial.com, DNS:www.paypal.com.tw, DNS:assets.braintreegateway.com, DNS:braintreefinancial.com, DNS:www.brand.braintreepayments.com, DNS:py.pl, DNS:www.paypal-deutschland.de, DNS:www.paypal.me, DNS:id.venmo.com, DNS:www.paypal.co.kr, DNS:id.zettle.com, DNS:cors.api.paypal.com, DNS:www.paypal.dk, DNS:login.paypal.com, DNS:pp-au.paypal.com, DNS:www.paypal.lu, DNS:pp-eu.paypal.com, DNS:www.paypal.com.es, DNS:www.paypal.de, DNS:www.paypal.co.th, DNS:www.paypal.com.my, DNS:www.paypal.com.mx, DNS:secure.paypal.com, DNS:www.paypal.com.ve, DNS:www.paypal.ph, DNS:www.paypal-latam.com, DNS:braintreepayments.com, DNS:www.paypal-forward.com, DNS:www.py.pl, DNS:m.paypal.it, DNS:history.paypal.com, DNS:www.paypal.co.uk, DNS:braintreecharge.com, DNS:t.paypal.com, DNS:braintreepaymentsolutions.com, DNS:c6.paypal.com, DNS:m.paypal.com, DNS:pics.paypal.com, DNS:www.braintreecharge.com, DNS:www.paypal.fr, DNS:business.paypal.com, DNS:id.joinhoney.com, DNS:financing.paypal.com, DNS:ssp.paypal.com, DNS:www.braintreepaymentsolutions.com, DNS:id.paypal.com, DNS:developer.paypal.com, DNS:fpdbs.paypal.com, DNS:www.paypal-marketing.pl, DNS:www.paypal.nl, DNS:www.paypal.no, DNS:www.paypal.fi, DNS:www.paypalobjects.com, DNS:www.paypal-mena.com, DNS:www.paypal.co.nz, DNS:www.paypal.com.pe, DNS:qwac.paypal.com, DNS:content.paypalobjects.com, DNS:www.paypal.at, DNS:id.braintreegateway.com, DNS:paypal.me, DNS:www.paypal.in, DNS:pointofsale-s.paypal.com, DNS:p.paypal.com, DNS:www.paypal.it, DNS:www.paypal.com.hk, DNS:www.paypal.ie, DNS:zettleintegrations.paypal.com, DNS:pp-in.paypal.com, DNS:c.paypal.com, DNS:www.paypal-gifts.com, DNS:m.paypal.co.uk, DNS:pep.paypal.com, DNS:www.paypal.pt, DNS:m.paypal.com.au, DNS:www.paypal.pl
-- | -----------------------------------
-- | This certificate's commonName, organizationName or altName (v3) do not appear in the malicious blocklist.
-- | -----------------------------------
-- | Issuer CommonName: DigiCert SHA2 Extended Validation Server CA
-- | Issuer organizationName:DigiCert Inc
-- | This certificate is not self signed as both subject and issuers are not the same. 
-- | -----------------------------------
-- | Not valid before: 2022-11-10T00:00:00
-- | Not valid after:  2023-11-10T23:59:59
-- |_The validity of this certificate is 365 days.



author = "Jacobo Casado / Angel Casanova"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = { "default", "safe", "discovery" }
dependencies = {"https-redirect"}

portrule = function(host, port)
  return shortport.ssl(host, port) or sslcert.isPortSupported(port) or sslcert.getPrepareTLSWithoutReconnect(port)
end

function date_to_string(date)
  if not date then
    return "MISSING"
  end
  if type(date) == "string" then
    return string.format("Can't parse; string is \"%s\"", date)
  else
    return datetime.format_timestamp(date)
  end
end

-- see if the file exists
function file_exists(file)
  local f = io.open(file, "rb")
  if f then f:close() end
  return f ~= nil
end

-- get all lines from a file, returns an empty 
-- list/table if the file does not exist
function lines_from(file)

  local lines = {}

  if not file_exists(file) then
    local file = 'list.csv'
    for line in io.lines(file) do 
      lines[#lines + 1] = line
    end
  else
    for line in io.lines(file) do 
      lines[#lines + 1] = line
    end
  end
  return lines
end


local function output_str(cert)

  if not have_openssl then
    -- OpenSSL is required to parse the cert, so just dump the PEM
    return "OpenSSL required to parse certificate.\n" .. cert.pem
  end
  local lines = {}

  lines[#lines + 1] = "\n-----------------------------------"
  -- Print information about the subject
  lines[#lines + 1] = "Subject CommonName: " .. cert.subject.commonName
  lines[#lines + 1] = "Subject organizationName:" .. cert.subject.organizationName
  lines[#lines + 1] = "Subject localityName:" .. cert.subject.localityName
  lines[#lines + 1] = "Subject countryName:" .. cert.subject.countryName
  -- Print information about the AltName
  if cert.extensions then
    for _, e in ipairs(cert.extensions) do
      if e.name == "X509v3 Subject Alternative Name" then
        lines[#lines + 1] = "Subject Alternative Name: " .. e.value
        break
      end
    end
  end
  -- Get the list.csv or the list= file specified by the user.
  local file = (stdnse.get_script_args("list") or "list.csv")

  local malicious_name = false
  local self_signed = false


  lines[#lines + 1] = "-----------------------------------"

  -- For each line, we check if the CommonName / Organization is in the blocklist
  local lines_file = lines_from(file)
  for k,v in pairs(lines_file) do
    if string.match(v, cert.subject.commonName) then 
      lines[#lines + 1] = "---------------WARNING---------------"
      lines[#lines + 1] = "Malicious subject commonName found ---> " .. cert.subject.commonName
      lines[#lines + 1] = "Found in line [" .. k .. "]: " .. v
      lines[#lines + 1] = "-----------------------------------"
      malicious_name = true
    elseif string.match(v, cert.subject.organizationName) then 
      lines[#lines + 1] = "---------------WARNING---------------"
      lines[#lines + 1] = "Malicious subject organizationName found ---> " .. cert.subject.organizationName
      lines[#lines + 1] = "Found in line [" .. k .. "]: " .. v
      lines[#lines + 1] = "-----------------------------------"
      malicious_name = true
    end
    -- We do the same with the fingerprint
    local sha1fingerprint = stdnse.tohex(cert:digest("sha1"))
    if string.match(v, sha1fingerprint) then 
          lines[#lines + 1] = "---------------WARNING---------------"
          lines[#lines + 1] = "Fingerprint of this certificate is on the blocklist ---> " .. sha1fingerprint
          lines[#lines + 1] = "Found in line [" .. k .. "]: " .. v
          lines[#lines + 1] = "-----------------------------------"
          malicious_name = true
    end
    -- If the certificate has extensions and the AltName extension is up, check it in the blocklist too:
    if cert.extensions then
      for _, e in ipairs(cert.extensions) do
        if e.name == "X509v3 Subject Alternative Name" then        
          -- lines[#lines + 1] = "Checking if the AltName is in the blocklist:"
	    if string.find(v, string.sub(e.value, 5) , 1, true) then 
            lines[#lines + 1] = "---------------WARNING---------------"
            lines[#lines + 1] = "Malicious ALTERNATIVE NAME found ---> " .. e.value
            lines[#lines + 1] = "Found in line [" .. k .. "]: " .. v
            lines[#lines + 1] =  "-----------------------------------" 
            malicious_name = true
            break
          end 
        end
      end
    end
  end

  -- Optional work: Check the issuer_list csv file
  -- if the issuer commonName or organizationName is also malicious
  -- (we could add + information about the issuer, as the fingerprint)
  local file = (stdnse.get_script_args("issuer_list") or "issuer_list.csv")

  local lines_file = lines_from(file)
  for k,v in pairs(lines_file) do

    if string.match(v, cert.issuer.commonName) then 
      lines[#lines + 1] = "---------------WARNING---------------"
      lines[#lines + 1] = "Malicious issuer commonName found ---> " .. cert.subject.commonName
      lines[#lines + 1] = "Found in line [" .. k .. "]: " .. v
      lines[#lines + 1] = "-----------------------------------"
      malicious_name = true
    elseif string.match(v, cert.issuer.organizationName) then 
      --print("CommonName not found")
      lines[#lines + 1] = "---------------WARNING---------------"
      lines[#lines + 1] = "Malicious issuer organizationName found ---> " .. cert.subject.organizationName
      lines[#lines + 1] = "Found in line [" .. k .. "]: " .. v
      lines[#lines + 1] = "-----------------------------------"
      malicious_name = true

    end
  end 
  -- We print if any of the certificate information appears in the blocklist.
  if malicious_name == false then
    lines[#lines + 1] = "This certificate does not appear in the blocklist."
  else
    lines[#lines + 1] = "Be careful! Some information of this certificate appears in the blocklist."
  end 

  lines[#lines + 1] = "-----------------------------------"

  -- We print issuer information
  lines[#lines + 1] = "Issuer CommonName: " .. cert.issuer.commonName
  lines[#lines + 1] = "Issuer organizationName:" .. cert.issuer.organizationName

  -- We check if it is self-signed
  if (cert.subject.commonName == cert.issuer.commonName
      and cert.subject.organizationName == cert.issuer.organizationName
      and cert.subject.localityName == cert.issuer.localityName
      and cert.subject.countryName == cert.issuer.countryName) then
        local self_signed = true 
        lines[#lines + 1] = "The certificate is self-signed as both subject and issuer certificates are the same."
      else
        lines[#lines + 1] = "This certificate is not self signed as both subject and issuers are not the same. " 
  end 

  lines[#lines + 1] = "-----------------------------------"


  -- Optional work: check if the validity is too short (<=30 days) or too long (>1000 days)
  lines[#lines + 1] = "Not valid before: " ..
  date_to_string(cert.validity.notBefore)
  lines[#lines + 1] = "Not valid after:  " ..
  date_to_string(cert.validity.notAfter)

  validityNotBefore = os.time(cert.validity.notBefore)
  validityNotAfter = os.time(cert.validity.notAfter)
  diffDays = os.difftime(validityNotAfter, validityNotBefore) / (24 * 60 * 60)
  floorDays = math.floor(diffDays)

  if floorDays <= 30 then
    lines[#lines + 1] = "---------------WARNING---------------"
    lines[#lines + 1] = "The validity of this certificate is TOO SHORT (" .. floorDays .. " days!)"
  elseif floorDays > 1000 then
    lines[#lines + 1] = "---------------WARNING---------------"
    lines[#lines + 1] = "The validity of this certificate is TOO LONG (" .. floorDays .. " days!)"
  else 
    lines[#lines + 1] = "The validity of this certificate is " .. floorDays .. " days."
  end

  return table.concat(lines, "\n")
end

action = function(host, port)
  host.targetname = tls.servername(host)
  local status, cert = sslcert.getCertificate(host, port)
  if ( not(status) ) then
    stdnse.debug1("getCertificate error: %s", cert or "unknown")
    return
  end

  return output_str(cert)
end



