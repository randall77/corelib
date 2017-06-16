package rtinfo

// table is a map from arch.version to information about
// runtime data structures.
var table = map[string]Info{}

type Info struct {
	Constants map[string]int64
}

func register(arch, version string, info Info) {
	table[arch+"."+version] = info
}

// Find returns all the information we have about the arch/version pair.
func Find(arch, version string) Info {
	return table[arch+"."+version]
}
