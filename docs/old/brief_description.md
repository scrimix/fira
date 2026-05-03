<aside>
💡

The goal of this project is to adapt and scale to the complexity of real work. Provide a tool to capture, understand, prioritize, plan and distribute tasks.

</aside>

…and some time later track “real” progress, capture the unknown.

<aside>
💡

Main feature is a **time block idea** - each task doesn’t have just start-end, but multiple blocks that can be allocated in calendar time - just like it happens in real life.

</aside>

Time blocks are work sessions and most tasks cannot be finished in one block. So, this is a task architecture feature that no current task management apps have. But, the problem is that migrating all task management is impossible, therefore the goal here is to link existing tasks and “add” time blocks to them.

### Task DB

- allows to create tasks without external system
- similar to notion task view
- image support could come later
- maybe mirror external tasks?
- support for time block feature

### Time Block DB

- task id
- task type notion / jira / local / gcal
- start - end
- planned | completed
- reduces time-left (from task estimates)
- read sync gcal events

### Calendar view

- weekly time block view
- task list with filter
    - by project
    - by person
    - by tag
    - by status
    - display time left
- uses priority sorting
- drag task into time block
- resize and move time block
- overlapping blocks split in half
- others gcal features like duplicate
- tick block as completed

### Task Inbox

- per project view
- similar to slack canvas or notion page
- Now block - recently done, in-progress and soon to-do
- Later block - backlog with no need to be precise
- simple and frictionless to edit
- hierarchy
    - [ ]  main task
        - [ ]  subtasks or subpoints
        - [ ]  go to description
        - [ ]  Update subtasks as description md points in jira/notion
- Export to Jira
- images in jira/notion description
- Tags - components, sprints, etc
- done tick
- Assign person
- Support stand-up process
    - create new tasks on the fly
    - see what is done or not
    - integrate with time blocks / estimates
- archive-to-done button

### Manage projects

- create a project with title and icon
- set task db source
- add users

### Snapshots

- daily snapshots
- track time block movement
- planning accuracy
- time-to-completion
    - from first TB allocation to task finished status