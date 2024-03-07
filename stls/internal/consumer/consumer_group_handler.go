package consumer

import (
	"github.com/IBM/sarama"
	"github.com/jacksonbarreto/DNSSECAnalyzer/pkg/logservice"
	"github.com/jacksonbarreto/WebGateScanner/stls/config"
	"github.com/jacksonbarreto/WebGateScanner/stls/scanner"
)

type Scanner interface {
}

type GroupHandler struct {
	scanner *scanner.Scanner
	Log     logservice.Logger
}

func NewConsumerGroupHandler(scanner *scanner.Scanner, logService logservice.Logger) *GroupHandler {
	return &GroupHandler{
		scanner: scanner,
		Log:     logService,
	}
}

func NewConsumerGroupHandlerDefault(scanner *scanner.Scanner) *GroupHandler {
	return NewConsumerGroupHandler(scanner, logservice.NewLogService(config.App().Id))
}

func (h *GroupHandler) Setup(session sarama.ConsumerGroupSession) error {
	return nil
}

func (h *GroupHandler) Cleanup(session sarama.ConsumerGroupSession) error {
	return nil
}

func (h *GroupHandler) ConsumeClaim(session sarama.ConsumerGroupSession, claim sarama.ConsumerGroupClaim) error {
	for message := range claim.Messages() {
		h.Log.Info("Message claimed: value = %s, timestamp = %v, topic = %s", string(message.Value), message.Timestamp, message.Topic)
		err := h.scanner.Scan(string(message.Value))
		if err != nil {
			h.Log.Error("Error scanning host '%s': %v", string(message.Value), err)
			continue
		}
		h.Log.Info("Message processed: value = %s, timestamp = %v, topic = %s", string(message.Value), message.Timestamp, message.Topic)
		session.MarkMessage(message, "")
	}
	return nil
}
