/*
 * Yokai, a simple MQTT "I'm alive" publisher for Dodomeki"
 * (c) jme@opium.io for crashdump.net
 * BSD LICENCE
 */

package main
import (
"fmt"
MQTT "github.com/eclipse/paho.mqtt.golang"
"crypto/hmac"
"crypto/sha256"
"encoding/base64"
//"os"
"time"
)

const mqtt_protocol  string = "tcp://"    // mqtt protocol to use (tls:// is prefered)
const mqtt_host      string = "localhost" // mqtt server fqdn or ip
const mqtt_port      string = "1883"   // mqtt server port
const mqtt_tls_ca    string = "xxxxxx" // tls certification autority public key
const mqtt_tls_cert  string = "xxxxxx" // tls client certificate
const mqtt_tls_key   string = "xxxxxx" // tls client secret key
const mqtt_topic     string = "dodomeki/alive" //topic to publish
const mqtt_id        string = "yokai-56290" //mqtt iD and topic trailing id.
const hmac_secret    string = "45c7ba5edbec11b38f8e1df5a816b4f1" //hmac secret to sign msg

const broker = mqtt_protocol + mqtt_host + ":" + mqtt_port
const mqtt_subscribe = mqtt_topic + "/" + mqtt_id

var message_string   string = ""

/*
var woopsie MQTT.MessageHandler = func() {
   fmt.Sprintf("Lost connection to the MQTT server")
}*/


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
   opts := MQTT.NewClientOptions().AddBroker(broker)
   opts.SetClientID(mqtt_id)
   opts.SetCleanSession(true)
   //opts.SetDefaultPublishHandler(f)
   //SetConnectionLostHandler(woopsie)
   c := MQTT.NewClient(opts)
   if token := c.Connect(); token.Wait() && token.Error() != nil {
      panic(token.Error())
   }

   var message string = build_message()
   //fmt.Printf("%s", message)
   text := fmt.Sprintf("%s", message)
   token := c.Publish(mqtt_subscribe, 0, false, text)
   token.Wait()
   c.Disconnect(250)
}//main
