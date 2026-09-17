# Schedule.Tests.ps1
# Unit tests for the recurring scan window: -Schedule and -Until

BeforeAll {
    . ([IO.Path]::Combine($PSScriptRoot, '..', '..', 'scanyx.ps1'))
}

Describe "ConvertTo-ScanyxDaySet" -Tag "Unit", "Schedule" {
    It "Reads the Spanish letters the way they are written here" {
        ConvertTo-ScanyxDaySet -Days "L,J,V" | Should -Be @(1, 4, 5)
        # M is martes and X miercoles, never the other way round
        ConvertTo-ScanyxDaySet -Days "M,X"   | Should -Be @(2, 3)
        ConvertTo-ScanyxDaySet -Days "S,D"   | Should -Be @(0, 6)
    }

    It "Reads English day names" {
        ConvertTo-ScanyxDaySet -Days "Mon,Thu,Fri" | Should -Be @(1, 4, 5)
        ConvertTo-ScanyxDaySet -Days "sunday"      | Should -Be @(0)
    }

    It "Reads full names with or without accents" {
        ConvertTo-ScanyxDaySet -Days "miércoles" | Should -Be @(3)
        ConvertTo-ScanyxDaySet -Days "miercoles" | Should -Be @(3)
        ConvertTo-ScanyxDaySet -Days "sábado"    | Should -Be @(6)
    }

    It "Expands a range" {
        ConvertTo-ScanyxDaySet -Days "L-V"     | Should -Be @(1, 2, 3, 4, 5)
        ConvertTo-ScanyxDaySet -Days "Mon-Fri" | Should -Be @(1, 2, 3, 4, 5)
    }

    It "Wraps a range that crosses the weekend" {
        # V-L is Friday, Saturday, Sunday, Monday
        ConvertTo-ScanyxDaySet -Days "V-L" | Should -Be @(0, 1, 5, 6)
    }

    It "Knows the words people use instead of listing days" {
        ConvertTo-ScanyxDaySet -Days "diario"      | Should -Be @(0, 1, 2, 3, 4, 5, 6)
        ConvertTo-ScanyxDaySet -Days "laborables"  | Should -Be @(1, 2, 3, 4, 5)
        ConvertTo-ScanyxDaySet -Days "weekdays"    | Should -Be @(1, 2, 3, 4, 5)
        ConvertTo-ScanyxDaySet -Days "finde"       | Should -Be @(0, 6)
        ConvertTo-ScanyxDaySet -Days "weekend"     | Should -Be @(0, 6)
    }

    It "Means every day when no day is named" {
        ConvertTo-ScanyxDaySet -Days ""   | Should -Be @(0, 1, 2, 3, 4, 5, 6)
        ConvertTo-ScanyxDaySet -Days "  " | Should -Be @(0, 1, 2, 3, 4, 5, 6)
    }

    It "Returns nothing for what it cannot read" {
        ConvertTo-ScanyxDaySet -Days "Z"      | Should -BeNullOrEmpty
        ConvertTo-ScanyxDaySet -Days "L,Z"    | Should -BeNullOrEmpty
        ConvertTo-ScanyxDaySet -Days "L-Z"    | Should -BeNullOrEmpty
    }
}

Describe "ConvertFrom-ScheduleSpec" -Tag "Unit", "Schedule" {
    It "Reads days plus a time range" {
        $r = ConvertFrom-ScheduleSpec -Spec "L,J,V 08:00-17:00"
        $r.Ok | Should -BeTrue
        $r.Windows.Count | Should -Be 1
        $r.Windows[0].Days | Should -Be @(1, 4, 5)
        $r.Windows[0].Start | Should -Be ([TimeSpan]::FromHours(8))
        $r.Windows[0].End | Should -Be ([TimeSpan]::FromHours(17))
        $r.Windows[0].CrossesMidnight | Should -BeFalse
    }

    It "Takes several windows separated by a semicolon" {
        $r = ConvertFrom-ScheduleSpec -Spec "L-V 08:00-17:00; S 10:00-14:00"
        $r.Ok | Should -BeTrue
        $r.Windows.Count | Should -Be 2
        $r.Windows[1].Days | Should -Be @(6)
    }

    It "Defaults to every day when only hours are given" {
        $r = ConvertFrom-ScheduleSpec -Spec "08:00-17:00"
        $r.Ok | Should -BeTrue
        $r.Windows[0].Days | Should -Be @(0, 1, 2, 3, 4, 5, 6)
    }

    It "Marks a range that ends before it starts as crossing midnight" {
        $r = ConvertFrom-ScheduleSpec -Spec "V 22:00-06:00"
        $r.Windows[0].CrossesMidnight | Should -BeTrue
    }

    It "Accepts a single-digit hour" {
        (ConvertFrom-ScheduleSpec -Spec "L-V 8:00-17:00").Windows[0].Start | Should -Be ([TimeSpan]::FromHours(8))
    }

    It "Returns no windows for an empty spec, and does not call it an error" {
        $r = ConvertFrom-ScheduleSpec -Spec ""
        $r.Ok | Should -BeTrue
        $r.Windows.Count | Should -Be 0
    }

    It "Explains what it could not read instead of guessing" -ForEach @(
        @{ spec = "L,J,V"           }
        @{ spec = "L,Z 08:00-17:00" }
        @{ spec = "L-V 25:00-17:00" }
        @{ spec = "L-V 08:00-08:00" }
        @{ spec = "cuando pueda"    }
    ) {
        $r = ConvertFrom-ScheduleSpec -Spec $spec
        $r.Ok | Should -BeFalse
        $r.Error | Should -Not -BeNullOrEmpty
    }
}

Describe "Get-ScheduleWindowFor" -Tag "Unit", "Schedule" {
    BeforeAll {
        # 2026-09-17 is a Thursday
        $script:Office = (ConvertFrom-ScheduleSpec -Spec "L,J,V 08:00-17:00").Windows
        $script:Night  = (ConvertFrom-ScheduleSpec -Spec "V 22:00-06:00").Windows
    }

    It "Is open between the hours of a day it covers" {
        $w = Get-ScheduleWindowFor -Windows $script:Office -Now ([datetime]"2026-09-17 12:00")
        $w | Should -Not -BeNullOrEmpty
        $w.Open  | Should -Be ([datetime]"2026-09-17 08:00")
        $w.Close | Should -Be ([datetime]"2026-09-17 17:00")
    }

    It "Opens on the hour and closes on the hour" {
        # Open is inclusive, close is not: at 17:00 the window is over
        Get-ScheduleWindowFor -Windows $script:Office -Now ([datetime]"2026-09-17 08:00") | Should -Not -BeNullOrEmpty
        Get-ScheduleWindowFor -Windows $script:Office -Now ([datetime]"2026-09-17 17:00") | Should -BeNullOrEmpty
    }

    It "Is shut outside its hours and on days it does not cover" {
        Get-ScheduleWindowFor -Windows $script:Office -Now ([datetime]"2026-09-17 07:59") | Should -BeNullOrEmpty
        # Saturday
        Get-ScheduleWindowFor -Windows $script:Office -Now ([datetime]"2026-09-19 12:00") | Should -BeNullOrEmpty
    }

    It "Stays open past midnight for a window that crosses it" {
        # Opened Friday night
        $w = Get-ScheduleWindowFor -Windows $script:Night -Now ([datetime]"2026-09-19 02:00")
        $w | Should -Not -BeNullOrEmpty
        $w.Open  | Should -Be ([datetime]"2026-09-18 22:00")
        $w.Close | Should -Be ([datetime]"2026-09-19 06:00")
        # and is shut once it closes on Saturday morning
        Get-ScheduleWindowFor -Windows $script:Night -Now ([datetime]"2026-09-19 06:30") | Should -BeNullOrEmpty
    }

    It "Returns nothing when there is no schedule at all" {
        Get-ScheduleWindowFor -Windows @() -Now ([datetime]"2026-09-17 12:00") | Should -BeNullOrEmpty
    }
}

Describe "Get-NextScheduleOpen" -Tag "Unit", "Schedule" {
    BeforeAll {
        $script:Office = (ConvertFrom-ScheduleSpec -Spec "L,J,V 08:00-17:00").Windows
    }

    It "Finds today's opening when it is still ahead" {
        Get-NextScheduleOpen -Windows $script:Office -Now ([datetime]"2026-09-17 06:00") |
            Should -Be ([datetime]"2026-09-17 08:00")
    }

    It "Finds tomorrow's once today's has passed" {
        # Thursday evening -> Friday morning
        Get-NextScheduleOpen -Windows $script:Office -Now ([datetime]"2026-09-17 18:00") |
            Should -Be ([datetime]"2026-09-18 08:00")
    }

    It "Skips the days the schedule does not cover" {
        # Friday evening -> Monday morning, over the weekend
        Get-NextScheduleOpen -Windows $script:Office -Now ([datetime]"2026-09-18 18:00") |
            Should -Be ([datetime]"2026-09-21 08:00")
    }

    It "Takes the earliest of several windows" {
        $two = (ConvertFrom-ScheduleSpec -Spec "J 15:00-16:00; J 09:00-10:00").Windows
        Get-NextScheduleOpen -Windows $two -Now ([datetime]"2026-09-17 06:00") |
            Should -Be ([datetime]"2026-09-17 09:00")
    }

    It "Returns nothing when there is no schedule" {
        Get-NextScheduleOpen -Windows @() -Now ([datetime]"2026-09-17 12:00") | Should -BeNullOrEmpty
    }
}

Describe "Resolve-DeadlineTime" -Tag "Unit", "Schedule" {
    BeforeAll {
        $script:Now = [datetime]"2026-09-17 16:00:00"
    }

    It "Takes a bare date as the end of that day" -ForEach @(
        @{ value = "2026-09-18"  }
        @{ value = "18/09/2026"  }
        @{ value = "2026/09/18"  }
    ) {
        (Resolve-DeadlineTime -Value $value -Now $script:Now).Time |
            Should -Be ([datetime]"2026-09-18 23:59:59")
    }

    It "Keeps an explicit time" {
        (Resolve-DeadlineTime -Value "2026-09-18 17:00" -Now $script:Now).Time |
            Should -Be ([datetime]"2026-09-18 17:00:00")
    }

    It "Accepts a relative span, like the other schedule parameters" {
        (Resolve-DeadlineTime -Value "+3d" -Now $script:Now).Time |
            Should -Be ([datetime]"2026-09-20 16:00:00")
    }

    It "Refuses a day that is already over" {
        $r = Resolve-DeadlineTime -Value "2020-01-01" -Now $script:Now
        $r.Ok | Should -BeFalse
        $r.Error | Should -Match 'past'
    }

    It "Returns nothing when no deadline was asked for" {
        $r = Resolve-DeadlineTime -Value "" -Now $script:Now
        $r.Ok | Should -BeTrue
        $r.Time | Should -BeNullOrEmpty
    }
}
