package consumer

import (
	"encoding/json"
	"github.com/IBM/sarama"
	"github.com/jacksonbarreto/WebGateScanner/DNSSECAnalyzer/config"
	"github.com/jacksonbarreto/WebGateScanner/DNSSECAnalyzer/internal/producer"
	"github.com/jacksonbarreto/WebGateScanner/DNSSECAnalyzer/internal/scanner"
	"github.com/jacksonbarreto/WebGateScanner/DNSSECAnalyzer/pkg/logservice"
	"github.com/jacksonbarreto/WebGateScanner/DNSSECAnalyzer/pkg/models"
	"github.com/jacksonbarreto/WebGateScanner/DNSSECAnalyzer/pkg/models/kafkaModels"
)

type AnalysisConsumerGroupHandler struct {
	scanner     *scanner.Scanner
	producer    *producer.Producer
	Topics      []string
	TopicsError []string
	Log         logservice.Logger
}

func NewAnalysisConsumerGroupHandler(scanner *scanner.Scanner, producer *producer.Producer, topics, topicsError []string, logService logservice.Logger) *AnalysisConsumerGroupHandler {
	return &AnalysisConsumerGroupHandler{
		scanner:     scanner,
		producer:    producer,
		Topics:      topics,
		TopicsError: topicsError,
		Log:         logService,
	}
}

func NewAnalysisConsumerGroupHandlerDefault(scanner *scanner.Scanner, producer *producer.Producer) *AnalysisConsumerGroupHandler {
	kafkaConfig := config.Kafka()
	topics := kafkaConfig.TopicsProducer
	topicsError := kafkaConfig.TopicsError
	logger := logservice.NewLogServiceDefault()
	return NewAnalysisConsumerGroupHandler(scanner, producer, topics, topicsError, logger)
}

func (h *AnalysisConsumerGroupHandler) Setup(session sarama.ConsumerGroupSession) error {
	return nil
}

func (h *AnalysisConsumerGroupHandler) Cleanup(session sarama.ConsumerGroupSession) error {
	return nil
}

func (h *AnalysisConsumerGroupHandler) ConsumeClaim(session sarama.ConsumerGroupSession, claim sarama.ConsumerGroupClaim) error {
	for message := range claim.Messages() {
		h.Log.Info("Message claimed: value = %s, timestamp = %v, topic = %s", string(message.Value), message.Timestamp, message.Topic)

		result, ScanErr := h.scanner.Scan(string(message.Value))
		if ScanErr != nil {
			h.handleError(string(message.Value), ScanErr)
			continue
		}
		kafkaMessage, msgErr := createKafkaMessage(result)
		if msgErr != nil {
			h.handleError(string(message.Value), ScanErr)
			continue
		}
		for _, topic := range h.Topics {
			h.Log.Info("Sending message to topic %s", topic)
			partition, offset, producerErr := h.producer.SendMessage(topic, kafkaMessage)
			if producerErr != nil {
				h.handleError(string(message.Value), ScanErr)
				continue
			}
			h.Log.Info("Message successfully sent to partition %d at offset %d", partition, offset)
		}
		session.MarkMessage(message, "")
	}
	return nil
}

func createKafkaMessage(result *models.Assessment) (string, error) {
	jsonData, err := json.Marshal(result)
	if err != nil {
		return "", err
	}
	return string(jsonData), nil
}

func createKafkaErrorMessage(url, errorMessage string) (string, error) {
	kafkaMessage := &kafkaModels.KafkaErrorMessage{
		Origin: config.App().Id,
		Url:    url,
		Error:  errorMessage,
	}
	jsonData, err := json.Marshal(kafkaMessage)
	if err != nil {
		return "", err
	}
	return string(jsonData), nil
}

func (h *AnalysisConsumerGroupHandler) handleError(url string, err error) {
	h.Log.Error("Error encountered for URL '%s' in '%s': %v", url, err)

	kafkaErrorMessage, kafkaErr := createKafkaErrorMessage(url, err.Error())
	if kafkaErr != nil {
		h.Log.Error("Error creating Kafka error message to '%s': %v", url, kafkaErr)
		return
	}

	for _, topic := range h.TopicsError {
		h.Log.Error("Sending error message to topic: %s", topic)
		partition, offset, producerErr := h.producer.SendMessage(topic, kafkaErrorMessage)
		if producerErr != nil {
			h.Log.Error("Error sending error message to Kafka topic '%s': %v", topic, producerErr)
			return
		}
		h.Log.Error("Error message successfully sent to partition %d at offset %d", partition, offset)
	}
}
