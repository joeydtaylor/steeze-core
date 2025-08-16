// pkg/electrician/sinks.go
package electrician

func loadSinksEnv() (s3 *s3Env, kafka *kafkaEnv, err error) {
	s3, err = loadS3Env()
	if err != nil {
		return nil, nil, err
	}
	kafka, err = loadKafkaEnv()
	if err != nil {
		return nil, nil, err
	}
	return s3, kafka, nil
}
