package producer

import (
	"github.com/IBM/sarama"
	"log"
)

type Producer struct {
	syncProducer sarama.SyncProducer
	topic        string
}

func NewProducer(topic string, brokers []string, maxRetry int) (*Producer, error) {
	configSarama := sarama.NewConfig()
	configSarama.Producer.Return.Successes = true
	configSarama.Producer.RequiredAcks = sarama.WaitForAll
	configSarama.Producer.Retry.Max = maxRetry

	syncProducer, err := sarama.NewSyncProducer(brokers, configSarama)
	if err != nil {
		log.Printf("Failed to create Kafka producer: %v", err)
		return nil, err
	}

	return &Producer{
		syncProducer: syncProducer,
		topic:        topic,
	}, nil
}

func (p *Producer) SendMessage(message string) (partition int32, offset int64, err error) {
	msg := &sarama.ProducerMessage{
		Topic: p.topic,
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
