package parse

func Fuzz(data []byte) int {
	_, err := RoleVariable(string(data))
	if err != nil {
		return 0
	}
	return 1
}
