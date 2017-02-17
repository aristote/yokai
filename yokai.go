/*
 * Yokai, a simple MQTT "I'm alive" publisher for Dodomeki"
 * (c) jme@opium.io for crashdump.net
 * BSD LICENCE
 */

package main
import (
"fmt"
"crypto/tls"
"crypto/x509"
MQTT "github.com/eclipse/paho.mqtt.golang"
"crypto/hmac"
"crypto/sha256"
"encoding/base64"
"time"
)

/*
Message for github password lurkers: those are not real production password
so don't bother...
*/
const mqtt_protocol  string = "tls://"    // mqtt protocol to use (tls:// is prefered)
const mqtt_host      string = "45.63.115.108" // mqtt server fqdn or ip
const mqtt_port      string = "8883"   // mqtt server port
const mqtt_login     string = "yokai" // mqtt server login
const mqtt_passwd    string = "161fc96b4a4e07bfb8bda0c4e985d2594e823f31" // mqtt server password 
const mqtt_topic     string = "dodomeki/alive" //topic to publish
const mqtt_id        string = "yokai-56290" //mqtt iD and topic trailing id.
const hmac_secret    string = "45c7ba5edbec11b38f8e1df5a816b4f1" //hmac secret to sign msg (this is an example)

const broker = mqtt_protocol + mqtt_host + ":" + mqtt_port
const mqtt_subscribe = mqtt_topic + "/" + mqtt_id

var message_string   string = ""

const mqtt_tls_ca = `-----BEGIN CERTIFICATE-----
MIIDozCCAougAwIBAgIJAKdfNTvWh5tmMA0GCSqGSIb3DQEBDQUAMGgxFjAUBgNV
BAMMDUEgTVFUVCBicm9rZXIxFjAUBgNVBAoMDWNyYXNoZHVtcC5uZXQxFDASBgNV
BAsMC2dlbmVyYXRlLUNBMSAwHgYJKoZIhvcNAQkBFhFub2NAY3Jhc2hkdW1wLm5l
dDAeFw0xNzAyMTYyMDUwMjJaFw0zMjAyMTMyMDUwMjJaMGgxFjAUBgNVBAMMDUEg
TVFUVCBicm9rZXIxFjAUBgNVBAoMDWNyYXNoZHVtcC5uZXQxFDASBgNVBAsMC2dl
bmVyYXRlLUNBMSAwHgYJKoZIhvcNAQkBFhFub2NAY3Jhc2hkdW1wLm5ldDCCASIw
DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALPVaQ8Ut20IpEEnBETJEzDBe51n
X3UMZe/2ZFmJBWai2mpvnG3Tcqfd8JdEFsqHBlUZ2F5DuKOsZjpiRgFyRhh4tW2Q
qPKIp+rMJOJdTvSU/ct/gD4STVAQFBQSWdrHm+qWmzztTQTpGuTjoG0gQBGj/n/8
CAL6Er3cMnncwzVScTRdjbU8Al4eio4zRRNo0bg9tj8zf9uXxViLKCbOXVenDY0v
cAfj9eSbLwh5b3wGlSo1amOBb8E/xgoq86RcduT71vare8puSSPCOwSjEnRfuco/
tIuEaERTrYPp8czGBo2pA5z0Lp0jvJ3d5DK2jF/g2LZyvMsZdg/yI0OTrOkCAwEA
AaNQME4wHQYDVR0OBBYEFFhKhZO96OYLn3mjBwdANnEwykYmMB8GA1UdIwQYMBaA
FFhKhZO96OYLn3mjBwdANnEwykYmMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEN
BQADggEBABYdNzUcvTX891sE6lrHAxw2NwgiMh45ERYZD12WyrDCJIAp+h5DP1sI
BvCakNTEbqXTEX2R7/5gQSMmgfnbGMDdf/qkFfB3qzx9VsJ1SYXR+FqUZ19ykD6Y
CJW+KrN5+hGtVv6HiNQrs5o8eaW4sD94HD1nV3Lt0/UFeL2hbbxC2HPAmRG3813/
fSSGg7MkQRAD2Wjt1hgfEG09wQJY9U9iCmgr9nAQpzN+5kQLZLjGksAG53HWV0sf
6UQ33NcofpL6njX+3mLNYOaKI808n4yorX/ffPBsZ+SJYYCdXyJmws2sCpQHymGg
F0NxUmaPTAifrf7Ia9JOg02Hh4cJlTo=
-----END CERTIFICATE-----`

func build_message() string {
// return the I'm alive message in the form of [current_epoch_time]:[hmac_verification]
// the [hmac_verification] is a sha256 hmac of [mqtt_id]:[the alive message itself]
// the hmac is to prevent a rogue device to send alive messages in place of another one
// the current time in epoch format provide the nonce against replay attacks
   now := time.Now()
   var  my_msg string = fmt.Sprintf("%d", now.Unix())
   var  my_verification string = mqtt_id + ":" + my_msg
   message_hmac := hmac.New(sha256.New, []byte(hmac_secret))
   message_hmac.Write([]byte(my_verification))
   myHmac := fmt.Sprintf("%s", base64.StdEncoding.EncodeToString(message_hmac.Sum(nil)))

   my_msg += ":" + myHmac
return my_msg
}//message

func main() {
	rootca := x509.NewCertPool()
    ok := rootca.AppendCertsFromPEM([]byte(mqtt_tls_ca))
    if !ok {
        panic("failed to parse root certificate")
    }

	tlsConfig := &tls.Config{RootCAs: rootca}

   opts := MQTT.NewClientOptions()
	opts.SetTLSConfig(tlsConfig) //we set the tls configuration
	opts.AddBroker(broker) //we add the broker
   opts.SetClientID(mqtt_id) //we set the mqtt id
   opts.SetCleanSession(true) // Sets true to client and server should remember state across restarts and reconnect
	opts.SetUsername(mqtt_login) // Set the mqtt server login
	opts.SetPassword(mqtt_passwd) // Set the mqtt server password
   c := MQTT.NewClient(opts) // Launch the client using the set options
   if token := c.Connect(); token.Wait() && token.Error() != nil {
      panic(token.Error())
   }

   var message string = build_message()
   text := fmt.Sprintf("%s", message)
   token := c.Publish(mqtt_subscribe, 0, false, text)
   token.Wait()
   c.Disconnect(250)
}//main
