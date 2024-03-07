package kafkaModels

type KafkaErrorMessage struct {
	Origin string `json:"origin"`
	Url    string `json:"url"`
	Error  string `json:"error"`
}
