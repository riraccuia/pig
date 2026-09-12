// Copyright 2026 Riccardo Raccuia
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package signaling

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	mqtt "github.com/eclipse/paho.mqtt.golang"
)

var (
	ErrMQTTFailure = errors.New("MQTT failure")
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

func (s *Signaler) connectMQTTClient() (mqtt.Client, error) {
	mqttOpts := getMQTTClientOptions(s.opts)

	mqttOpts.SetConnectionLostHandler(func(client mqtt.Client, err error) {
		if s.opts.Logger != nil {
			s.opts.Logger.Errorf("SIG: MQTT connection lost: %v", err)
		}
		close(s.mqttLostConn)
		s.mqttLostConn = make(chan struct{})
	})

	client := mqtt.NewClient(mqttOpts)

	if token := client.Connect(); token.Wait() && token.Error() != nil {
		return nil, errors.Join(ErrMQTTFailure, token.Error())
	}

	return client, nil
}

// connectAndPublish connects to MQTT and publishes the message.
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

// getTopicPrefix returns the topic prefix, it will use the ID if it is set, or
// the input string if not. Then the ID or input string is hashed with the encryption key
// and base64 encoded.
func (s *Signaler) getTopicPrefix(inputStr string) string {
	useStr := inputStr
	if s.opts.ServerID != "" {
		useStr = s.opts.ServerID
	}
	// the topic prefix is the sha256 hash of the target address
	topicPrefix := sha256.Sum256(append([]byte(useStr), s.opts.EncryptionKey...))
	// base64 encode the topic prefix
	topicPrefixStr := strings.ToLower(base64.URLEncoding.EncodeToString(topicPrefix[:]))
	// remove slashes from the topic prefix
	topicPrefixStr = strings.ReplaceAll(topicPrefixStr, "/", "")
	return topicPrefixStr
}
