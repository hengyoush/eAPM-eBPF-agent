package agent

/*
#cgo LDFLAGS: -lrt
#include <time.h>
*/
import "C"

func GetMachineStartTimeNano() uint64 {
	var timestamp C.struct_timespec

	C.clock_gettime(C.CLOCK_REALTIME, &timestamp)
	nowEpochTime := uint64(timestamp.tv_sec)*1000000000 + uint64(timestamp.tv_nsec)
	// fmt.Printf("real time: %d, seconds: %d, nano:  %d\n", nowEpochTime, timestamp.tv_sec, timestamp.tv_nsec)

	C.clock_gettime(C.CLOCK_MONOTONIC, &timestamp)
	machineRunningDuration := uint64(timestamp.tv_sec)*1000000000 + uint64(timestamp.tv_nsec)
	// fmt.Printf("mono time: %d\n", machineRunningDuration)

	launchEpochTime := nowEpochTime - machineRunningDuration
	// fmt.Printf("machine start time: %d\n", launchEpochTime)
	return launchEpochTime
}
