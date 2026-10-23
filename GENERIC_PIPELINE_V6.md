# Generic Agentic DevSecOps v6

Fixes Jenkins `MethodTooLargeException`.

Large generic build and unit-test decision trees were moved from Jenkins Groovy/CPS into helper Python scripts generated in the Jenkins workspace at runtime. Jenkins still owns orchestration and execution, and all eight stages remain visible.
