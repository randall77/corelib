package rtinfo

// table is a map from arch.version to information about
// runtime data structures.
var table = map[string]Info{}

type Info struct {
	WordSize  int64
	Structs   map[string]StructInfo
	Constants map[string]int64
	// TODO: others?
}

type StructInfo struct {
	Size   int64
	Fields map[string]FieldInfo
}

type FieldInfo struct {
	Off int64
	Typ string
}

func register(arch, version string, info Info) {
	table[arch+"."+version] = info
}

// Find returns all the information we have about the arch/version pair.
func Find(arch, version string) Info {
	return table[arch+"."+version]
}
