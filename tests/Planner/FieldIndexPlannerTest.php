<?php
namespace ParagonIE\CipherSweet\Tests\Planner;

use ParagonIE\CipherSweet\Exception\PlannerException;
use ParagonIE\CipherSweet\Planner\FieldIndexPlanner;
use PHPUnit\Framework\TestCase;

/**
 * Class FieldIndexPlannerTest
 * @package ParagonIE\CipherSweet\Tests\Planner
 */
class FieldIndexPlannerTest extends TestCase
{
    public function testCoincidenceCount()
    {
        $planner = (new FieldIndexPlanner())
            ->setEstimatedPopulation(1 << 16)
            ->addExistingIndex('name', 8, PHP_INT_MAX)
            ->addExistingIndex('first_initial_last_name', 4, PHP_INT_MAX);

        $this->assertGreaterThan(0, $planner->getCoincidenceCount());
        $this->assertGreaterThan(20, $planner->withPopulation(1 << 20)->getCoincidenceCount());
        $this->assertLessThan(20, $planner->getCoincidenceCount());
    }

    public function testRecommend()
    {
        $planner = (new FieldIndexPlanner())
            ->setEstimatedPopulation(1 << 16)
            ->addExistingIndex('name', 4, PHP_INT_MAX)
            ->addExistingIndex('first_initial_last_name', 4, PHP_INT_MAX);

        $this->assertSame(['min' => 1, 'max' => 7], $planner->recommend());
        $this->assertSame(1, $planner->recommendLow());
        $this->assertSame(7, $planner->recommendHigh());

        // With a lower input domain:
        $this->assertSame(['min' => 1, 'max' => 7], $planner->recommend(15));
        $this->assertSame(1, $planner->recommendLow());
        $this->assertSame(7, $planner->recommendHigh());

        // With an even lower input domain:
        $this->assertSame(['min' => 1, 'max' => 7], $planner->recommend(8));
        $this->assertSame(1, $planner->recommendLow(8));
        $this->assertSame(7, $planner->recommendHigh(8));

        $plan2 = $planner->withPopulation(1 << 31);
        $this->assertSame(['min' => 8, 'max' => 22], $plan2->recommend());
        $this->assertSame(8, $plan2->recommendLow());
        $this->assertSame(22, $plan2->recommendHigh());

        // No existing fields:
        $plan3 = (new FieldIndexPlanner())
            ->setEstimatedPopulation(1 << 16);
        $this->assertSame(['min' => 8, 'max' => 15], $plan3->recommend());
        $this->assertSame(['min' => 8, 'max' => 14], $plan3->recommend(14));
        $this->assertSame(['min' => 4, 'max' => 7], $plan3->withPopulation(1 << 8)->recommend());
        $this->assertSame(['min' => 4, 'max' => 7], $plan3->withPopulation(1 << 8)->recommend(7));
        $this->assertSame(['min' => 16, 'max' => 30], $plan3->withPopulation(1 << 31)->recommend());
        $this->assertSame(['min' => 16, 'max' => 29], $plan3->withPopulation(1 << 31)->recommend(29));
        $this->assertSame(['min' => 16, 'max' => 24], $plan3->withPopulation(1 << 31)->recommend(24));

        // What if we're adding a very-low-entropy input? Recommend a much smaller index!
        $this->assertSame(['min' => 1, 'max' => 8], $plan3->withPopulation(1 << 31)->recommend(8));

    }

    public function testPlannerExtremes()
    {
        $planner = (new FieldIndexPlanner())
            ->setEstimatedPopulation(2)
            ->addExistingIndex('name', 32, PHP_INT_MAX)
            ->addExistingIndex('first_initial_last_name', 16, PHP_INT_MAX)
            ->addExistingIndex('initials', 16, PHP_INT_MAX);
        try {
            $planner->recommend();
            $this->fail(
                'Planner should throw an exception if it cannot offer safe recommendations.'
            );
        } catch (PlannerException $ex) {
            $this->assertSame('There is no safe upper bound', $ex->getMessage());
        }

        $planner = (new FieldIndexPlanner())
            ->setEstimatedPopulation((1 << 31) - 1);
        $this->assertSame(['min' => 16, 'max' => 30], $planner->recommend());
        $this->assertSame(['min' => 16, 'max' => 17], $planner->recommend(17));
        $this->assertSame(['min' => 16, 'max' => 29], $planner->recommend(29));
        $this->assertSame(['min' => 16, 'max' => 30], $planner->recommend(30));
    }
}
