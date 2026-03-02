import random

# Set parameters
num_files = 10
total_entries_per_file = 10000
max_value = 1000000

# Number of entries shared by all files
common_entries = 500

# Number of unique entries in each file
unique_entries = total_entries_per_file - common_entries

# Generate the common data shared across all files
common_data = set()
while len(common_data) < common_entries:
    common_data.add(f"element{random.randint(1, max_value)}")

# Generate each file
for i in range(num_files):
    file_name = f"set_{i}"

    # Generate unique data for the current file
    unique_data = set()
    while len(unique_data) < unique_entries:
        entry = f"element{random.randint(1, max_value)}"

        # Ensure the entry is not already in the common data
        # and not duplicated within the current file
        if entry not in common_data and entry not in unique_data:
            unique_data.add(entry)

    # Combine common data and unique data, then write them to the file
    with open(file_name, 'w') as f:
        all_data = list(common_data) + list(unique_data)
        random.shuffle(all_data)  # Shuffle the order of entries
        for entry in all_data:
            f.write(f"{entry}\n")

    # For the first file only, also write all its entries into a query file
    if i == 0:
        with open('query', 'w') as query_file:
            query_file.writelines(f"{entry}\n" for entry in all_data)

# Print a summary after generation is complete
print(
    f"Generated {num_files} files with {total_entries_per_file} entries each, "
    f"including {common_entries} common entries."
)