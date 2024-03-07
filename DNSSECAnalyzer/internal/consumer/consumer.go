package consumer

import (
	"context"
	"github.com/IBM/sarama"
	"github.com/jacksonbarreto/WebGateScanner/DNSSECAnalyzer/config"
	"log"
)

type Consumer struct {
	consumerGroup        sarama.ConsumerGroup
	topics               []string
	consumerGroupHandler sarama.ConsumerGroupHandler
}

func NewConsumer(brokers []string, group string, topics []string, consumerGroupHandler sarama.ConsumerGroupHandler) (*Consumer, error) {
	configConsumerGroup := sarama.NewConfig()
	configConsumerGroup.Version = sarama.V2_0_0_0
	configConsumerGroup.Consumer.Return.Errors = true
	configConsumerGroup.Consumer.Offsets.Initial = sarama.OffsetOldest

	consumer, err := sarama.NewConsumerGroup(brokers, group, configConsumerGroup)
	if err != nil {
		log.Printf("Error creating consumer group client: %v", err)
		return nil, err
	}

	return &Consumer{consumerGroup: consumer, topics: topics, consumerGroupHandler: consumerGroupHandler}, nil
}

func NewConsumerDefault(consumerGroupHandler sarama.ConsumerGroupHandler) (*Consumer, error) {
	kafkaConfig := config.Kafka()
	brokerList := kafkaConfig.Brokers
	groupID := kafkaConfig.GroupID
	topics := kafkaConfig.TopicsConsumer
	return NewConsumer(brokerList, groupID, topics, consumerGroupHandler)
}

// TODO: Analyze if this function work with multiple messages in the same scanner

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
