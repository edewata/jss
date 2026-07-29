#!/usr/bin/python3

import argparse
import logging
import sys
from typing import Dict, Tuple, List

logger = logging.getLogger(__name__)


def parse_input(filename: str) -> Dict[str, int]:
    '''
    Parse input file and return a map of object class name to count.
    '''
    data = {}
    try:
        with open(filename, 'r') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                parts = line.split()
                if len(parts) != 2:
                    logger.error('File %s does not contain exactly 2 columns', filename)
                    sys.exit(1)
                class_name, count = parts
                try:
                    data[class_name] = int(count)
                except ValueError:
                    logger.error('File %s has invalid count value: %s', filename, count)
                    sys.exit(1)
    except FileNotFoundError:
        logger.error('File %s not found', filename)
        sys.exit(1)
    except Exception as e:
        logger.error('Unable to read %s: %s', filename, e)
        sys.exit(1)
    return data


def calculate_heap_changes(snapshot1: Dict[str, int], snapshot2: Dict[str, int]) -> List[Tuple[str, int, int, float]]:
    '''
    Calculate changes and change percentages between two heap snapshots.

    Returns a list of tuples: (class_name, before, after, change, percentage)
    '''
    results = []

    # Find all objects present in either snapshots
    objects = set(snapshot1.keys()) | set(snapshot2.keys())

    for class_name in objects:
        before = snapshot1.get(class_name, 0)
        after = snapshot2.get(class_name, 0)
        change = after - before

        # Calculate percentage of change
        if before == 0:
            # New object appeared in second file
            if change > 0:
                percentage = float('inf')
            else:
                continue
        else:
            percentage = (change / before) * 100

        # Only include classes that have changed
        if change > 0:
            results.append((class_name, before, after, change, percentage))

    return results


def main():
    parser = argparse.ArgumentParser(
        description='Check changes between two heap snapshots'
    )
    parser.add_argument('snapshot1', help='First heap snapshot')
    parser.add_argument('snapshot2', help='Second heap snapshot')

    args = parser.parse_args()

    # Parse both params
    snapshot1 = parse_input(args.snapshot1)
    snapshot2 = parse_input(args.snapshot2)

    if not snapshot1:
        logger.error('First heap snapshot is empty or invalid')
        sys.exit(1)

    if not snapshot2:
        logger.error('Second heap snapshot is empty or invalid')
        sys.exit(1)

    # Calculate heap changes
    results = calculate_heap_changes(snapshot1, snapshot2)

    if not results:
        print('No heap changes')
        return

    # Sort by percentage (descending), then by change (descending), then by class name (ascending)
    results.sort(key=lambda x: (-x[4], -x[3], x[0]))

    # Display results
    print(f'{"Object":<60}  {"Before":>7}  {"After":>7}  {"Change":>7}  {"Percentage":>10}')
    print('=' * 100)

    for i, (class_name, before, after, change, percentage) in enumerate(results):
        if percentage == float('inf'):
            percentage_str = 'NEW'
        else:
            percentage_str = f'{percentage:+.0f}%'

        # Truncate long class names
        display_name = class_name[:60] if len(class_name) <= 60 else class_name[:57] + '...'

        print(f'{display_name:<60}  {before:>7}  {after:>7}  {change:>+7}  {percentage_str:>10}')


if __name__ == '__main__':
    main()
