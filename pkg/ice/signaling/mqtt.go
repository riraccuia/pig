package signaling

import (
	"crypto/tls"

	mqtt "github.com/eclipse/paho.mqtt.golang"
)

func getMQTTClientOptions(opts *Options) *mqtt.ClientOptions {
	// Create MQTT client options
	mqttOpts := mqtt.NewClientOptions().
		AddBroker(opts.BrokerURL).
		SetCleanSession(true).
		SetTLSConfig(&tls.Config{
			InsecureSkipVerify: true,
		})
	if opts.ClientID != "" {
		mqttOpts.SetClientID(opts.ClientID)
	}
	if opts.Username != "" {
		mqttOpts.SetUsername(opts.Username)
	}
	if opts.Password != "" {
		mqttOpts.SetPassword(opts.Password)
	}
	return mqttOpts
}
