package stark

import (
	"encoding/hex"
	"fmt"
	"os"
	"testing"
	"time"
	"runtime"
	"github.com/ayushn2/go-stark.git/algebra"
	"github.com/ayushn2/go-stark.git/poly"
	"github.com/stretchr/testify/assert"
	"bytes"
)

// Measure CPU utilization
func measureCPUUsage() float64 {
	var cpuUsage float64


	numCPU := runtime.NumCPU()
	start := runtime.NumGoroutine()
	startTime := time.Now()

	done := make(chan struct{})
	go func() {
		time.Sleep(1 * time.Second) // Measure over 1 sec
		end := runtime.NumGoroutine()
		elapsed := time.Since(startTime).Seconds()
		cpuUsage = float64(end-start) / elapsed * 100 / float64(numCPU)
		close(done)
	}()

	<-done
	return cpuUsage
}

// Measure memory usage
func measureMemoryUsage() (uint64, uint64) {
    var memStats runtime.MemStats
    runtime.ReadMemStats(&memStats)
    return memStats.Alloc / 1024, memStats.Sys / 1024 // Report both allocated and total system memory in KB
}
func TestZKGen(t *testing.T) {
	paramBytes, err := os.ReadFile("domainparams.json")
	if err != nil {
		t.Fatal("failed to unmarshal domain params with error :", err)
	}

	paramsInstance := &DomainParameters{}
	err = paramsInstance.UnmarshalJSON(paramBytes)
	if err != nil {
		t.Fatal("failed to unmarshal domain params with error :", err)
	}
	_, g, _, _, _, _, f, _, _ := paramsInstance.Trace, paramsInstance.GeneratorG, paramsInstance.SubgroupG, paramsInstance.GeneratorH, paramsInstance.SubgroupH, paramsInstance.EvaluationDomain, paramsInstance.Polynomial, paramsInstance.PolynomialEvaluations, paramsInstance.EvaluationRoot
	fsChannel := NewChannel()
	fsChannel.Send(paramsInstance.EvaluationRoot)

	// Measure memory usage before proof generation
	memBefore, sysBefore := measureMemoryUsage()

	// Parameter generation test
	t.Run("TestParamGen", func(t *testing.T) {
		t.Log("Trace length :", len(paramsInstance.Trace))
		t.Log("Subgroup G generator :", paramsInstance.GeneratorG)
		t.Log("Subgroup order:", len(paramsInstance.SubgroupG))
		t.Log("Subgroup H generator : ", paramsInstance.GeneratorH)
		t.Log("Subgroup order :", len(paramsInstance.SubgroupH))
		t.Log("Polynomial :", paramsInstance.Polynomial.String())
		// Save polynomial to a file
		err := os.WriteFile("polynomial_output.txt", []byte(paramsInstance.Polynomial.String()), 0644)
		if err != nil {
			t.Fatal("failed to write polynomial to file:", err)
		}

		t.Log("Eval domain order :", len(paramsInstance.EvaluationDomain))
		t.Log("Merkle Commitment of evaluations :", hex.EncodeToString(paramsInstance.EvaluationRoot))
		t.Log("Chanel ", hex.EncodeToString(fsChannel.State))
	})

	// Proof generation and verification test
	t.Run("TestProve", func(t *testing.T) {
		f := f.Clone(0)

		quoPolyConstraint1, quoPolyConstraint2, quoPolyConstraint3 := GenerateProgramConstraints(f, g)

		if quoPolyConstraint1.Eval(algebra.FromInt64(2718), PrimeField.Modulus()).Cmp(algebra.FromInt64(2509888982)) != 0 {
			t.Fatal("first constraint not verified : wrong evaluation at x = 2718")
		}

		if quoPolyConstraint2.Eval(algebra.FromInt64(5772), PrimeField.Modulus()).Cmp(algebra.FromInt64(232961446)) != 0 {
			t.Fatal("second constraint not verified : wrong evaluation at 5772")
		}

		// Verify the third constraint
		// The expected value is calculated based on the polynomial evaluation at x = 31415
		// This value should match the expected output of the third constraint polynomial
		// which is derived from the program constraints defined in GenerateProgramConstraints
		// The expected value is 2090051528, which is the result of evaluating
		// the third polynomial at x = 31415 in the finite field defined by PrimeField.Modulus()
		// This is a crucial step to ensure the integrity of the zk-STARK proof generation
		// and verification process, as it confirms that the polynomial constraints are correctly
		// defined and evaluated.

		expected := algebra.FromInt64(2090051528)
		actual := quoPolyConstraint3.Eval(algebra.FromInt64(31415), PrimeField.Modulus())
		if actual.Cmp(expected) != 0 {
			t.Fatal("third constraint not verified : wrong evaluation at 31415 , expected :", expected, " got :", actual)
		}

		// To generate succinct proofs we transform the three polynomial validity checks
		constraints := []poly.Polynomial{quoPolyConstraint1, quoPolyConstraint2, quoPolyConstraint3}
		compositionPoly := poly.NewPolynomialInts(0)
		for i := 0; i < 3; i++ {
			randomFE := fsChannel.RandFE(PrimeField.Modulus())
			comb := constraints[i].Mul(poly.NewPolynomialBigInt(randomFE), PrimeField.Modulus())
			compositionPoly = compositionPoly.Add(comb, PrimeField.Modulus())
		}
		t.Log("Composition Polynomial :", compositionPoly)

		// Now we evaluate the composition polynomial on the evaluation domain
		compositionPolyEvals := make([]algebra.FieldElement, len(paramsInstance.EvaluationDomain))
		for idx, elem := range paramsInstance.EvaluationDomain {
			eval := compositionPoly.Eval(elem.Big(), PrimeField.Modulus())
			compositionPolyEvals[idx] = PrimeField.NewFieldElement(eval)
		}
		compositionPolyEvalsRoot := DomainHash(compositionPolyEvals)

		t.Log("Composition Polynomial Evaluations Root :", hex.EncodeToString(compositionPolyEvalsRoot))
		fsChannel.Send(compositionPolyEvalsRoot)

		

		// Start timing the proof verification
		startTime := time.Now()

		friDomains, friPolys, friLayers, friRoots := GenerateFRICommitment(compositionPoly, paramsInstance.EvaluationDomain, compositionPolyEvals, compositionPolyEvalsRoot, *fsChannel)

		// Log FRI layers and roots information
		assert.Len(t, friLayers, 11)
		assert.Len(t, friLayers[len(friLayers)-1], 8)
		expectedLastLayerConstant := PrimeField.NewFieldElementFromInt64(2550486681)
		for _, x := range friLayers[len(friLayers)-1] {
			assert.True(t, x.Equal(expectedLastLayerConstant))
		}

		assert.Equal(t, friPolys[len(friPolys)-1].Degree(), 0)

		t.Log("FRI-Layer Count :", len(friLayers))
		t.Log("FRI-Root Count", len(friRoots))
		t.Log("FRI Domains Count :", len(friDomains))
		t.Log("Last Layer Root :", hex.EncodeToString(friRoots[len(friRoots)-1]))
		t.Log("Last Layer Terms")
		for _, x := range friLayers[len(friLayers)-1] {
			t.Log("x = ", x.String())
		}
		t.Log("Channel Proof", fsChannel.Proof)

		

		// Now perform proof verification
		cosetEvals := paramsInstance.PolynomialEvaluations
		FRIDecommit(fsChannel, cosetEvals, friLayers)

		// End timing the proof verification
		elapsedTime := time.Since(startTime)

		var starkProofBuffer bytes.Buffer

		// Store Merkle roots (commitments)
		for _, root := range friRoots {
			starkProofBuffer.Write(root)
		}

		// Store FRI layers (intermediate proofs)
		for _, layer := range friLayers {
			for _, elem := range layer {
				starkProofBuffer.Write(elem.Big().Bytes())
			}
		}

		// Convert fsChannel.Proof (which is []string) into a single []byte
		for _, proofPart := range fsChannel.Proof {
			starkProofBuffer.Write([]byte(proofPart)) // Convert each string to []byte
		}

		// Print the actual zk-STARK proof size
		fmt.Printf("=== zk-STARK Proof Size ===\n")
		fmt.Printf("zk-STARK Proof Size (Raw Bytes): %d bytes\n", starkProofBuffer.Len())

		// Log proof size in Go test output
		t.Logf("zk-STARK Proof Size: %d bytes", starkProofBuffer.Len())

		// Log the proof verification time
		t.Logf("Proof verification time: %v", elapsedTime)

		// Final proof data
		t.Log("Final Proof Uncompressed", fsChannel.Proof)
	})

	// Measure memory usage after proof generation
	memAfter, sysAfter := measureMemoryUsage()

	// Print memory results
	fmt.Printf("Memory Usage Before: %d KB, After: %d KB\n", memBefore, memAfter)
	fmt.Printf("Total System Memory Before: %d KB, After: %d KB\n", sysBefore, sysAfter)

	// Log results
	t.Logf("Memory Usage Before: %d KB, After: %d KB", memBefore, memAfter)
	t.Logf("Total System Memory Before: %d KB, After: %d KB", sysBefore, sysAfter)
}



func TestProofGenerationTime(t *testing.T) {

	// Measure CPU usage before proof generation
	cpuBefore := measureCPUUsage()
	startTimeCPU := time.Now()

	paramBytes, err := os.ReadFile("domainparams.json")
	if err != nil {
		t.Fatal("failed to read domainparams.json:", err)
	}

	paramsInstance := &DomainParameters{}
	err = paramsInstance.UnmarshalJSON(paramBytes)
	if err != nil {
		t.Fatal("failed to unmarshal domain params:", err)
	}

	_, g, _, _, _, _, f, _, _ := paramsInstance.Trace, paramsInstance.GeneratorG, paramsInstance.SubgroupG, paramsInstance.GeneratorH, paramsInstance.SubgroupH, paramsInstance.EvaluationDomain, paramsInstance.Polynomial, paramsInstance.PolynomialEvaluations, paramsInstance.EvaluationRoot
	fsChannel := NewChannel()
	fsChannel.Send(paramsInstance.EvaluationRoot)

	startTime := time.Now()

	f = f.Clone(0)

	quoPolyConstraint1, quoPolyConstraint2, quoPolyConstraint3 := GenerateProgramConstraints(f, g)
	constraints := []poly.Polynomial{quoPolyConstraint1, quoPolyConstraint2, quoPolyConstraint3}

	compositionPoly := poly.NewPolynomialInts(0)
	for i := 0; i < 3; i++ {
		randomFE := fsChannel.RandFE(PrimeField.Modulus())
		comb := constraints[i].Mul(poly.NewPolynomialBigInt(randomFE), PrimeField.Modulus())
		compositionPoly = compositionPoly.Add(comb, PrimeField.Modulus())
	}

	compositionPolyEvals := make([]algebra.FieldElement, len(paramsInstance.EvaluationDomain))
	for idx, elem := range paramsInstance.EvaluationDomain {
		eval := compositionPoly.Eval(elem.Big(), PrimeField.Modulus())
		compositionPolyEvals[idx] = PrimeField.NewFieldElement(eval)
	}
	compositionPolyEvalsRoot := DomainHash(compositionPolyEvals)

	GenerateFRICommitment(compositionPoly, paramsInstance.EvaluationDomain, compositionPolyEvals, compositionPolyEvalsRoot, *fsChannel)

	elapsedTime := time.Since(startTime)
	fmt.Printf("Proof generation time: %v\n", elapsedTime)

	t.Logf("Proof generated successfully in %v", elapsedTime)

	// Measure CPU usage after proof generation
	cpuAfter := measureCPUUsage()
	elapsedTimeCPU := time.Since(startTimeCPU)

	// Print CPU results
	fmt.Printf("=== zk-STARK CPU Utilization ===\n")
	fmt.Printf("Proof Generation Time: %v\n", elapsedTimeCPU)
	fmt.Printf("CPU Usage Before: %.2f%%\n", cpuBefore)
	fmt.Printf("CPU Usage After: %.2f%%\n", cpuAfter)

	// Log results in Go test output
	t.Logf("Proof generated successfully in %v", elapsedTimeCPU)
	t.Logf("CPU Usage Before: %.2f%%, After: %.2f%%", cpuBefore, cpuAfter)

}

