package utils

func RemoveEmptyStrings(input []string) []string {
	var result []string
	for _, s := range input {
		if s != "" {
			result = append(result, s)
		}
	}
	return result
}
