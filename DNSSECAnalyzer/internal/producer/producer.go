package producer

import (
	"github.com/IBM/sarama"
	"github.com/jacksonbarreto/WebGateScanner/DNSSECAnalyzer/config"
	"log"
)

type Producer struct {
	syncProducer sarama.SyncProducer
}

func NewProducer(brokers []string) (*Producer, error) {
	configSarama := sarama.NewConfig()
	configSarama.Producer.Return.Successes = true
	configSarama.Producer.RequiredAcks = sarama.WaitForAll
	configSarama.Producer.Retry.Max = 5

	syncProducer, err := sarama.NewSyncProducer(brokers, configSarama)
	if err != nil {
		log.Printf("Failed to create Kafka producer: %v", err)
		return nil, err
	}

	return &Producer{syncProducer: syncProducer}, nil
}

func NewProducerDefault() (*Producer, error) {
	kafkaConfig := config.Kafka()
	brokerList := kafkaConfig.Brokers
	return NewProducer(brokerList)
}

func (p *Producer) SendMessage(topic string, message string) (partition int32, offset int64, err error) {
	msg := &sarama.ProducerMessage{
		Topic: topic,
		Value: sarama.StringEncoder(message),
	}

	partition, offset, err = p.syncProducer.SendMessage(msg)
	if err != nil {
		log.Printf("Failed to send message: %v", err)
		return 0, 0, err
	}

	return partition, offset, nil
}

func (p *Producer) Close() error {
	if err := p.syncProducer.Close(); err != nil {
		log.Printf("Failed to close Kafka producer: %v", err)
		return err
	}
	return nil
}
