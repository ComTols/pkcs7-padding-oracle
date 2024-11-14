package cases

type SpecialCase struct {
	Content []byte
	IV      []byte
}

var (
	SpecialCases []SpecialCase = CreateSpecialCases()
)

func CreateSpecialCases() []SpecialCase {
	return []SpecialCase{
		{
			Content: []byte{0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03},
			IV:      make([]byte, 16),
		},
	}
}
