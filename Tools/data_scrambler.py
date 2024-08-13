import os
import json
import random
import logging
from typing import Any, Dict, List

from Src.Utils.logger import setup_logger

# Initialize the logger
logger = setup_logger("data_scrambler_logger")


class DataScrambler:
    """
    Class to scramble and unscramble data for enhanced security.
    """

    def __init__(self, scramble_key: int = 42):
        self.scramble_key = scramble_key
        random.seed(self.scramble_key)

    def scramble_data(self, data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Scramble the input data by shuffling the order of dictionaries and
        scrambling the values within each dictionary.

        :param data: List of dictionaries to scramble
        :return: Scrambled list of dictionaries
        """
        scrambled_data = random.sample(data, len(data))  # Shuffle the order of dictionaries
        logger.debug(f"Shuffled data order: {scrambled_data}")

        for record in scrambled_data:
            for key in record:
                record[key] = self._scramble_value(record[key])

        logger.info("Data scrambling completed.")
        return scrambled_data

    def unscramble_data(self, scrambled_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Unscramble the scrambled data by reversing the scrambling process.

        :param scrambled_data: List of scrambled dictionaries to unscramble
        :return: Unscrambled list of dictionaries
        """
        for record in scrambled_data:
            for key in record:
                record[key] = self._unscramble_value(record[key])

        unscrambled_data = sorted(scrambled_data, key=lambda x: x.get("timestamp", 0))
        logger.info("Data unscrambling completed.")
        return unscrambled_data

    def _scramble_value(self, value: Any) -> Any:
        """
        Private method to scramble individual values.

        :param value: Value to scramble
        :return: Scrambled value
        """
        if isinstance(value, str):
            scrambled_value = ''.join(random.sample(value, len(value)))
            logger.debug(f"Scrambled string value: {scrambled_value}")
            return scrambled_value
        elif isinstance(value, int):
            scrambled_value = value + self.scramble_key
            logger.debug(f"Scrambled integer value: {scrambled_value}")
            return scrambled_value
        elif isinstance(value, float):
            scrambled_value = value * self.scramble_key
            logger.debug(f"Scrambled float value: {scrambled_value}")
            return scrambled_value
        else:
            return value

    def _unscramble_value(self, value: Any) -> Any:
        """
        Private method to unscramble individual values.

        :param value: Value to unscramble
        :return: Unscrambled value
        """
        if isinstance(value, str):
            unscrambled_value = ''.join(sorted(value))
            logger.debug(f"Unscrambled string value: {unscrambled_value}")
            return unscrambled_value
        elif isinstance(value, int):
            unscrambled_value = value - self.scramble_key
            logger.debug(f"Unscrambled integer value: {unscrambled_value}")
            return unscrambled_value
        elif isinstance(value, float):
            unscrambled_value = value / self.scramble_key
            logger.debug(f"Unscrambled float value: {unscrambled_value}")
            return unscrambled_value
        else:
            return value


def main():
    data_scrambler = DataScrambler()

    # Example data
    data = [
        {"timestamp": 1622471123, "value": 10},
        {"timestamp": 1622471183, "value": 20},
        {"timestamp": 1622471243, "value": 30},
        {"timestamp": 1622471303, "value": 40},
        {"timestamp": 1622471363, "value": 50}
    ]

    # Scramble data
    scrambled_data = data_scrambler.scramble_data(data)
    logger.info(f"Scrambled Data: {scrambled_data}")

    # Save scrambled data to a file
    with open("data/scrambled_data.json", 'w') as file:
        json.dump(scrambled_data, file)

    # Load scrambled data from a file
    with open("data/scrambled_data.json", 'r') as file:
        loaded_scrambled_data = json.load(file)

    # Unscramble data
    unscrambled_data = data_scrambler.unscramble_data(loaded_scrambled_data)
    logger.info(f"Unscrambled Data: {unscrambled_data}")


if __name__ == "__main__":
    main()
