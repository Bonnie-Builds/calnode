<script lang="ts">
	import { onMount } from 'svelte';
	import { api, type Booking } from '$lib/api';

	let bookings = $state<Booking[]>([]);
	let loading = $state(true);
	let error = $state('');
	let month = $state(new Date(new Date().getFullYear(), new Date().getMonth(), 1));

	const monthLabel = $derived(new Intl.DateTimeFormat(undefined, { month: 'long', year: 'numeric' }).format(month));
	const days = $derived.by(() => {
		const firstWeekday = month.getDay();
		const count = new Date(month.getFullYear(), month.getMonth() + 1, 0).getDate();
		const result: Array<Date | null> = Array.from({ length: firstWeekday }, () => null);
		for (let day = 1; day <= count; day += 1) result.push(new Date(month.getFullYear(), month.getMonth(), day));
		while (result.length % 7 !== 0) result.push(null);
		return result;
	});

	onMount(async () => {
		try {
			const response = await api.get<{ items: Booking[] }>('/v1/bookings');
			bookings = response.items;
		} catch {
			error = 'Your calendar is temporarily unavailable.';
		} finally {
			loading = false;
		}
	});

	function dateKey(date: Date): string {
		return `${date.getFullYear()}-${date.getMonth()}-${date.getDate()}`;
	}

	function bookingsFor(date: Date): Booking[] {
		const key = dateKey(date);
		return bookings
			.filter((booking) => dateKey(new Date(booking.start_at)) === key)
			.sort((left, right) => left.start_at.localeCompare(right.start_at));
	}

	function moveMonth(offset: number): void {
		month = new Date(month.getFullYear(), month.getMonth() + offset, 1);
	}

	function timeLabel(value: string): string {
		return new Intl.DateTimeFormat(undefined, { hour: 'numeric', minute: '2-digit' }).format(new Date(value));
	}

	function attendeeLabel(booking: Booking): string {
		return booking.attendees.map((attendee) => attendee.name).join(', ') || 'Meeting';
	}
</script>

<svelte:head><title>Calendar — Bonnie</title></svelte:head>

<div class="mx-auto flex h-full min-h-[32rem] max-w-6xl flex-col">
	<header class="mb-4 flex items-center justify-between gap-4">
		<div>
			<h1 class="text-xl font-semibold tracking-tight">Calendar</h1>
			<p class="text-sm text-muted-foreground">Your Calnode bookings and meeting schedule.</p>
		</div>
		<div class="flex items-center gap-2">
			<button class="rounded-md border px-3 py-1.5 text-sm hover:bg-muted" onclick={() => moveMonth(-1)} aria-label="Previous month">←</button>
			<p class="min-w-36 text-center text-sm font-medium">{monthLabel}</p>
			<button class="rounded-md border px-3 py-1.5 text-sm hover:bg-muted" onclick={() => moveMonth(1)} aria-label="Next month">→</button>
		</div>
	</header>

	{#if loading}
		<div class="flex flex-1 items-center justify-center text-sm text-muted-foreground">Loading calendar…</div>
	{:else if error}
		<div class="rounded-md border border-destructive/30 bg-destructive/5 p-4 text-sm text-destructive">{error}</div>
	{:else}
		<div class="grid grid-cols-7 border-l border-t bg-card text-center text-xs font-medium text-muted-foreground">
			{#each ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'] as weekday}
				<div class="border-b border-r px-2 py-2">{weekday}</div>
			{/each}
		</div>
		<div class="grid flex-1 grid-cols-7 border-l bg-card">
			{#each days as day}
				<div class="min-h-24 border-b border-r p-1.5 {day ? '' : 'bg-muted/20'}">
					{#if day}
						<p class="mb-1 text-right text-xs text-muted-foreground">{day.getDate()}</p>
						{#each bookingsFor(day) as booking}
							<div class="mb-1 truncate rounded px-1.5 py-1 text-[11px] {booking.status === 'cancelled' ? 'bg-muted text-muted-foreground line-through' : 'bg-primary/10 text-primary'}" title={attendeeLabel(booking)}>
								<span class="font-medium">{timeLabel(booking.start_at)}</span> {attendeeLabel(booking)}
							</div>
						{/each}
					{/if}
				</div>
			{/each}
		</div>
	{/if}
</div>
