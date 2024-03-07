package consumer

type KafkaMessage struct {
	Type    string `json:"type"`
	Payload string `json:"payload"`
}
