package consumer

import (
	"context"
	"github.com/IBM/sarama"
	"github.com/jacksonbarreto/WebGateScanner/sadi/config"
	"log"
)

type Consumer struct {
	consumerGroup        sarama.ConsumerGroup
	topics               []string
	consumerGroupHandler sarama.ConsumerGroupHandler
}

func NewConsumer(brokers []string, group string, topics []string, consumerHandler sarama.ConsumerGroupHandler) (*Consumer, error) {
	configConsumerGroup := sarama.NewConfig()
	configConsumerGroup.Version = sarama.V2_0_0_0
	configConsumerGroup.Consumer.Return.Errors = true
	configConsumerGroup.Consumer.Offsets.Initial = sarama.OffsetOldest

	consumer, err := sarama.NewConsumerGroup(brokers, group, configConsumerGroup)
	if err != nil {
		log.Printf("Error creating consumer group client: %v", err)
		return nil, err
	}

	return &Consumer{consumerGroup: consumer, topics: topics, consumerGroupHandler: consumerHandler}, nil
}

func NewConsumerDefault(processorMap ProcessorMap) (*Consumer, error) {
	kafkaConfig := config.Kafka()
	brokerList := kafkaConfig.Brokers
	groupID := kafkaConfig.GroupID
	topics := kafkaConfig.Topics
	consumerHandler := NewMappingCoordinator(processorMap)
	return NewConsumer(brokerList, groupID, topics, consumerHandler)
}

func (c *Consumer) Consume() error {
	handler := c.consumerGroupHandler
	ctx := context.Background()

	for {
		err := c.consumerGroup.Consume(ctx, c.topics, handler)
		if err != nil {
			log.Printf("Error from consumer: %v", err)
			return err
		}
	}
}
