package dicescript

import (
	"testing"
)

func TestRollDistribution(t *testing.T) {
	src := NewChaChaSource()
	const (
		sides        = 6
		tries        = 1000000 // 增加采样次数
		significance = 0.05    // 显著性水平
	)
	counts := make([]int, sides)

	for i := 0; i < tries; i++ {
		result := Roll(src, IntType(sides), 0)
		if result <= 0 || result > sides {
			t.Fatalf("骰子结果超出范围: %d", result)
		}
		counts[result-1]++
	}

	// 计算卡方统计量
	expected := float64(tries) / float64(sides)
	chiSquare := 0.0
	for _, count := range counts {
		diff := float64(count) - expected
		chiSquare += (diff * diff) / expected
	}

	// 自由度为sides-1=5时，显著性水平0.05的临界值为11.07
	// 如果卡方统计量大于临界值，则拒绝均匀分布的假设
	criticalValue := 11.07
	if chiSquare > criticalValue {
		t.Errorf("卡方检验失败: χ² = %.4f > %.4f, 分布可能不均匀\n次数统计:", chiSquare, criticalValue)
		for i, count := range counts {
			deviation := 100 * (float64(count)/expected - 1)
			t.Errorf("%d: %d (预期%.0f, 偏差%.2f%%)", i+1, count, expected, deviation)
		}
	} else {
		t.Logf("卡方检验通过: χ² = %.4f <= %.4f", chiSquare, criticalValue)
		for i, count := range counts {
			deviation := 100 * (float64(count)/expected - 1)
			t.Logf("%d: %d (预期%.0f, 偏差%.2f%%)", i+1, count, expected, deviation)
		}
	}
	// 计算均值
	sums := 0.0
	for result, count := range counts {
		sums += float64(result+1) * float64(count)
	}
	means := sums / float64(tries)
	t.Logf("均值: %.2f", means)

}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}
