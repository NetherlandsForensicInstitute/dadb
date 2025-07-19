# dadb - Data Analysis DataBase

DADB is a simple database framework that can be used to store "Data" and
"Models" in a single SQLite database. It is intended to solve a basic
requirement that is common in Data Analysis: storing and combining results of
various different analysis tools for futher (combined) analysis.

## Basic concepts

DADB is a database framework that can be used to store "Data" and "Models" in a
single SQLite database. Data objects are binary blobs of arbitrary size data
that can be used as file-like objects. Models are ways to store user-defined
objects that consists one or more member fields. An object that is stored in a
model in the database is considered a "modelitem". Each member field can hold
(a sequence of) one of the basic datatypes:

* DateTime
* Date
* Integer
* String
* Bytes
* Bool
* TimeDelta
* Float

In addition, a member field can hold (a sequence of) the following:

* a Data object
* an Enum value
* a modelitem of some other model.

Models can be defined in Python code in a simple language. A model for storing
a 'measurement', for example, could look something like this:

    modeldef = model_definition('measurement',
                                [field_definition('name', str, nullable=False),
                                 field_definition('tstart', _datetime),
                                 field_definition('tend', _datetime),
                                 field_definition('samplecount', int, nullable=False),
                                 field_definition('samples, (int,)),
                                 field_definition('category', Category, nullable=False),
                                 field_definition('raw_data', Data),
                                 field_definition('notes', str)],
                                'measurement model',
                                1,
                                implicit_dedup=True,
                                fail_on_dup=True)

Here, Category is an enum that needs to be defined separately. For an
explanation of the other parts of a model definition, please read the
documentation in the code.

## Status

This is an experimental framework that may contain bugs or other problems that
emerge in your specific usage scenario. Please perform thorough testing and
validation before relying on any results.

## Caveats

When using DADB you should take care of the following:

* DADB is intended for use on a single analysis computer and for best
  performance the database should be stored on a local HDD (or preferably SSD).

* Make sure the database is written to from a single process only. When you
  want to inspect the results in a viewer such as sqlitebrowser during
  analysis, make sure to open the database read-only.

* Documentation and examples are not yet available.

## Installation

Checkout the repository as follows:

    git clone https://github.com/NetherlandsForensicInstitute/dadb.git

Run the following from the checked-out repository:

    make install

## License

Copyright (C) 2023-2025 Netherlands Forensic Institute - MIT License
