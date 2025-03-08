package main

import (
	"fmt"
	"os"
	"runtime"
	"time"
)

// Measure CPU utilization
func measureCPUUsage() float64 {
	var cpuUsage float64
	numCPU := runtime.NumCPU()
	startTime := time.Now()

	done := make(chan struct{})
	go func() {
		start := runtime.NumGoroutine()
		time.Sleep(1 * time.Second) // Measure over 1 sec
		end := runtime.NumGoroutine()
		elapsed := time.Since(startTime).Seconds()
		cpuUsage = float64(end-start) / elapsed * 100 / float64(numCPU)
		close(done)
	}()

	<-done
	return cpuUsage
}

func main() {
	// Load domain parameters
	paramBytes, err := os.ReadFile("domainparams.json")
	if err != nil {
		fmt.Println("Failed to read domainparams.json:", err)
		return
	}

	paramsInstance := &DomainParameters{}
	err = paramsInstance.UnmarshalJSON(paramBytes)
	if err != nil {
		fmt.Println("Failed to unmarshal domain params:", err)
		return
	}

	// Measure CPU usage before proof generation
	cpuBefore := measureCPUUsage()

	startTime := time.Now()

	// Run zk-STARK proof generation
	_, g, _, _, _, _, f, _, _ := paramsInstance.Trace, paramsInstance.GeneratorG, paramsInstance.SubgroupG, paramsInstance.GeneratorH, paramsInstance.SubgroupH, paramsInstance.EvaluationDomain, paramsInstance.Polynomial, paramsInstance.PolynomialEvaluations, paramsInstance.EvaluationRoot
	fsChannel := NewChannel()
	fsChannel.Send(paramsInstance.EvaluationRoot)

	f = f.Clone(0)
	quoPolyConstraint1, quoPolyConstraint2, quoPolyConstraint3 := GenerateProgramConstraints(f, g)
	constraints := []poly.Polynomial{quoPolyConstraint1, quoPolyConstraint2, quoPolyConstraint3}

	// Compute composition polynomial
	compositionPoly := poly.NewPolynomialInts(0)
	for i := 0; i < 3; i++ {
		randomFE := fsChannel.RandFE(PrimeField.Modulus())
		comb := constraints[i].Mul(poly.NewPolynomialBigInt(randomFE), PrimeField.Modulus())
		compositionPoly = compositionPoly.Add(comb, PrimeField.Modulus())
	}

	// Evaluate composition polynomial on evaluation domain
	compositionPolyEvals := make([]algebra.FieldElement, len(paramsInstance.EvaluationDomain))
	for idx, elem := range paramsInstance.EvaluationDomain {
		eval := compositionPoly.Eval(elem.Big(), PrimeField.Modulus())
		compositionPolyEvals[idx] = PrimeField.NewFieldElement(eval)
	}

	// Generate FRI commitment
	compositionPolyEvalsRoot := DomainHash(compositionPolyEvals)
	GenerateFRICommitment(compositionPoly, paramsInstance.EvaluationDomain, compositionPolyEvals, compositionPolyEvalsRoot, *fsChannel)

	elapsedTime := time.Since(startTime)

	// Measure CPU usage after proof generation
	cpuAfter := measureCPUUsage()

	// Print Results
	fmt.Println("=== zk-STARK CPU Utilization Data ===")
	fmt.Printf("Proof Generation Time: %v\n", elapsedTime)
	fmt.Printf("CPU Usage Before: %.2f%%\n", cpuBefore)
	fmt.Printf("CPU Usage After: %.2f%%\n", cpuAfter)
}