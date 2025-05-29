package signaling

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"strings"

	mqtt "github.com/eclipse/paho.mqtt.golang"
)

func getMQTTClientOptions(opts *Options) *mqtt.ClientOptions {
	// Create MQTT client options
	mqttOpts := mqtt.NewClientOptions().
		AddBroker(opts.BrokerURL).
		SetAutoReconnect(true).
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

func connectMQTTClient(opts *Options) (mqtt.Client, error) {
	mqttOpts := getMQTTClientOptions(opts)

	mqttOpts.SetConnectionLostHandler(func(client mqtt.Client, err error) {
		if opts.Logger != nil {
			opts.Logger.Errorf("MQTT connection lost: %v", err)
		}
	})

	client := mqtt.NewClient(mqttOpts)

	if token := client.Connect(); token.Wait() && token.Error() != nil {
		return nil, token.Error()
	}
	return client, nil
}

// connectAndPublish connects to MQTT and publishes the message
func (s *Signaler) connectAndPublish(topic string, payload []byte) (err error) {
	// Publish the message
	if token := s.mqttClient.Publish(topic, 0, false, payload); token.Wait() && token.Error() != nil {
		return fmt.Errorf("failed to publish ICE payload: %w", token.Error())
	}

	return nil
}

func (s *Signaler) connectAndSubscribe(topic string, handler mqtt.MessageHandler) (err error) {
	if token := s.mqttClient.Subscribe(topic, 0, handler); token.Wait() && token.Error() != nil {
		return fmt.Errorf("failed to subscribe to topic %s: %w", topic, token.Error())
	}
	return nil
}

// getTopicPrefix returns the topic prefix for the given string
func (s *Signaler) getTopicPrefix(str string) string {
	// the topic prefix is the sha256 hash of the target address
	topicPrefix := sha256.Sum256(append([]byte(str), s.opts.EncryptionKey...))
	// base64 encode the topic prefix
	topicPrefixStr := strings.ToLower(base64.StdEncoding.EncodeToString(topicPrefix[:]))
	// remove slashes from the topic prefix
	topicPrefixStr = strings.ReplaceAll(topicPrefixStr, "/", "")
	return topicPrefixStr
}
