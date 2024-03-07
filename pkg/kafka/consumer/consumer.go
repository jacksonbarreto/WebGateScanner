package consumer

import (
	"context"
	"github.com/IBM/sarama"
	"log"
)

type Consumer struct {
	consumerGroup        sarama.ConsumerGroup
	topics               []string
	consumerGroupHandler sarama.ConsumerGroupHandler
	context              context.Context
}

func New(brokers []string, group string, topics []string, consumerGroupHandler sarama.ConsumerGroupHandler,
	context context.Context) (*Consumer, error) {
	configConsumerGroup := sarama.NewConfig()
	configConsumerGroup.Version = sarama.V2_0_0_0
	configConsumerGroup.Consumer.Return.Errors = true
	configConsumerGroup.Consumer.Offsets.Initial = sarama.OffsetOldest

	consumer, err := sarama.NewConsumerGroup(brokers, group, configConsumerGroup)
	if err != nil {
		log.Printf("Error creating consumer group client: %v", err)
		return nil, err
	}

	return &Consumer{
		consumerGroup:        consumer,
		topics:               topics,
		consumerGroupHandler: consumerGroupHandler,
		context:              context,
	}, nil
}

// TODO: Analyze if this function work with multiple messages in the same scanner

func (c *Consumer) Consume() error {
	handler := c.consumerGroupHandler
	ctx := c.context

	for {
		err := c.consumerGroup.Consume(ctx, c.topics, handler)
		if err != nil {
			log.Printf("Error from consumer: %v", err)
			return err
		}
	}
}
