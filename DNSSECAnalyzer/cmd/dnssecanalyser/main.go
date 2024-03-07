package main

import (
	"context"
	"github.com/jacksonbarreto/WebGateScanner/DNSSECAnalyzer/config"
	"github.com/jacksonbarreto/WebGateScanner/DNSSECAnalyzer/internal/scanner"
	"github.com/jacksonbarreto/WebGateScanner/pkg/kafka/consumer"
	"github.com/jacksonbarreto/WebGateScanner/pkg/kafka/producer"
)

const configFilePath = ""

func main() {
	config.InitConfig(configFilePath)
	dnsScanner := scanner.NewScannerDefault()

	kafkaProducer, producerErr := producer.New(config.Kafka().TopicsProducer[0], config.Kafka().Brokers, config.Kafka().MaxRetry)
	if producerErr != nil {
		panic(producerErr)
	}
	defer kafkaProducer.Close()

	handler := consumer.NewAnalysisConsumerGroupHandlerDefault(dnsScanner, kafkaProducer)

	kafkaConsumer, consumerErr := consumer.New(config.Kafka().Brokers, config.Kafka().Group, config.Kafka().TopicsConsumer, handler, context.Background())
	if consumerErr != nil {
		panic(consumerErr)
	}

	consumeErr := kafkaConsumer.Consume()
	if consumeErr != nil {
		panic(consumeErr)
	}
}
