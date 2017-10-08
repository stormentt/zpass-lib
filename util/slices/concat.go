package slices

// combine combines all the byte slices into one big byte slice
func Combine(slices ...[]byte) []byte {
	var length int
	for _, slice := range slices {
		length += len(slice)
	}

	// Pre allocating an array & using copy() is quicker than using append() because append() creates a bunch of new arrays each time it runs out of room
	// Pre allocating also uses less memory
	tmp := make([]byte, length)

	var pos int
	for _, slice := range slices {
		pos += copy(tmp[pos:], slice)
	}

	return tmp
}
