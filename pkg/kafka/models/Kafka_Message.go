package models

type KafkaErrorMessage struct {
	Origin string `json:"origin"`
	Url    string `json:"url"`
	Error  string `json:"error"`
}

type KafkaMessage struct {
	Origin string `json:"origin"`
}
