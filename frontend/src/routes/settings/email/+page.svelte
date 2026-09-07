<script lang="ts">
	import { onMount } from 'svelte';
	import { api, type User, type EmailSettings } from '$lib/api';
	import { currentUser } from '$lib/stores';
	import { Button } from '$lib/components/ui/button';
	import { Input } from '$lib/components/ui/input';
	import { Label } from '$lib/components/ui/label';
	import { Switch } from '$lib/components/ui/switch';
	import { toast } from 'svelte-sonner';
	import { saveOnCmdS } from '$lib/save-shortcut';
	import { createAsyncFlag } from '$lib/async-action.svelte';

	const loadingFlag = createAsyncFlag(true);
	const savingFlag = createAsyncFlag();
	const testingFlag = createAsyncFlag();

	let emailSettings = $state<EmailSettings | null>(null);
	let smtpHost = $state('');
	let smtpPort = $state('587');
	let smtpUser = $state('');
	let smtpPass = $state('');
	let smtpTLS = $state(false);
	let smtpStartTLS = $state(true);
	let emailFrom = $state('');
	let emailFromName = $state('Bonnie');

	let userEmail = $state('');
	let statusLabel = $derived(!emailSettings?.enabled
		? 'Not configured'
		: emailSettings.verified ? 'Verified' : 'Configured, unverified');
	let statusTone = $derived(!emailSettings?.enabled
		? 'bg-amber-50 text-amber-700'
		: emailSettings.verified ? 'bg-green-50 text-green-700' : 'bg-blue-50 text-blue-700');
	let dotTone = $derived(!emailSettings?.enabled
		? 'bg-amber-400'
		: emailSettings.verified ? 'bg-green-500' : 'bg-blue-500');

	onMount(() => loadingFlag.run(async () => {
		const [me, email] = await Promise.all([
			api.get<User>('/v1/users/me'),
			api.get<EmailSettings>('/v1/settings/email'),
		]);
		userEmail = me.email;
		emailSettings = email;
		smtpHost = email.smtp_host;
		smtpPort = email.smtp_port || '587';
		smtpUser = email.smtp_user;
		smtpTLS = email.smtp_tls;
		smtpStartTLS = email.smtp_starttls;
		emailFrom = email.email_from;
		emailFromName = email.email_from_name || 'Bonnie';
	}, 'Could not load email settings'));

	async function save() {
		await savingFlag.run(async () => {
			const body: {
				smtp_host: string; smtp_port: string; smtp_user: string;
				smtp_tls: boolean; smtp_starttls: boolean;
				email_from: string; email_from_name: string; smtp_pass?: string;
			} = {
				smtp_host: smtpHost, smtp_port: smtpPort, smtp_user: smtpUser,
				smtp_tls: smtpTLS, smtp_starttls: smtpStartTLS,
				email_from: emailFrom, email_from_name: emailFromName,
			};
			if (smtpPass) body.smtp_pass = smtpPass;
			emailSettings = await api.patch<EmailSettings>('/v1/settings/email', body);
			smtpPass = '';
			toast.success('Email settings saved');
		}, 'Could not save email settings');
	}

	async function test() {
		await testingFlag.run(async () => {
			try {
				await api.post('/v1/settings/email/test');
			} catch (error) {
				if (error instanceof Error && error.message === 'Email is not configured — save SMTP settings first') {
					throw new Error('Save your settings first, then try again.');
				}
				throw error;
			}
			emailSettings = await api.get<EmailSettings>('/v1/settings/email');
			toast.success(`Test email sent to ${userEmail}`);
		}, 'Could not send test email');
	}

	function useResendPreset() {
		smtpHost = 'smtp.resend.com';
		smtpPort = '587';
		smtpUser = 'resend';
		smtpTLS = false;
		smtpStartTLS = true;
	}
</script>

<svelte:window onkeydown={saveOnCmdS(save, () => !savingFlag.active)} />

{#if !$currentUser?.is_admin}
	<p class="text-sm text-muted-foreground">Admin access required.</p>
{:else}

{#if loadingFlag.active}
	<p class="py-8 text-sm text-muted-foreground">Loading…</p>
{:else}
	<div class="max-w-lg">
		<div class="rounded-lg border bg-card p-6">
			<div class="mb-4 flex items-start justify-between gap-2">
				<div>
					<h2 class="text-sm font-semibold">Email</h2>
					<p class="mt-0.5 text-xs text-muted-foreground">SMTP settings for sending booking emails.</p>
				</div>
				{#if emailSettings !== null}
					<span class="flex items-center gap-1.5 rounded-full px-2 py-0.5 text-xs font-medium {statusTone}">
						<span class="h-1.5 w-1.5 rounded-full {dotTone}"></span>
						{statusLabel}
					</span>
				{/if}
			</div>

			<div class="space-y-4">
				<div class="flex items-start justify-between gap-4 rounded-md border bg-muted/30 p-3">
					<div>
						<p class="text-sm font-medium">Resend</p>
						<p class="mt-0.5 text-xs text-muted-foreground">
							{#if emailSettings?.managed_by_environment}
								Managed by the deployment. Rotate <code>RESEND_API_KEY</code> there and restart this instance.
							{:else}
								Use your Resend API key as the SMTP password and a verified From address.
							{/if}
						</p>
					</div>
					{#if !emailSettings?.managed_by_environment}
						<Button variant="outline" onclick={useResendPreset}>Use preset</Button>
					{/if}
				</div>

				<div class="grid grid-cols-3 gap-3">
					<div class="col-span-2 space-y-1.5">
						<Label for="smtp-host">SMTP host</Label>
						<Input id="smtp-host" type="text" placeholder="smtp.resend.com" bind:value={smtpHost} disabled={emailSettings?.managed_by_environment} />
					</div>
					<div class="space-y-1.5">
						<Label for="smtp-port">Port</Label>
						<Input id="smtp-port" type="text" placeholder="587" bind:value={smtpPort} disabled={emailSettings?.managed_by_environment} />
					</div>
				</div>

				<div class="grid grid-cols-2 gap-3">
					<div class="space-y-1.5">
						<Label for="smtp-user">Username</Label>
						<Input id="smtp-user" type="text" placeholder="resend" bind:value={smtpUser} disabled={emailSettings?.managed_by_environment} />
					</div>
					<div class="space-y-1.5">
						<Label for="smtp-pass">Password</Label>
						<Input id="smtp-pass" type="password"
							placeholder={emailSettings?.smtp_pass_set ? '•••••••• (stored)' : 'Enter password'}
							bind:value={smtpPass} disabled={emailSettings?.managed_by_environment} />
						{#if emailSettings?.smtp_pass_set && !smtpPass}
							<p class="text-xs text-muted-foreground">Stored — leave blank to keep it.</p>
						{/if}
					</div>
				</div>

				<div class="grid grid-cols-2 gap-3">
					<div class="space-y-1.5">
						<Label for="email-from">From address</Label>
						<Input id="email-from" type="email" placeholder="bookings@example.com" bind:value={emailFrom} disabled={emailSettings?.managed_by_environment} />
					</div>
					<div class="space-y-1.5">
						<Label for="email-from-name">From name</Label>
						<Input id="email-from-name" type="text" placeholder="Bonnie" bind:value={emailFromName} disabled={emailSettings?.managed_by_environment} />
					</div>
				</div>

				<div class="space-y-2 rounded-md border p-3">
					<p class="text-xs font-medium text-muted-foreground">TLS / encryption</p>
					<div class="flex items-center justify-between gap-4">
						<div>
							<Label for="smtp-starttls" class="cursor-pointer font-normal">STARTTLS</Label>
							<p class="text-xs text-muted-foreground">Recommended for port 587</p>
						</div>
						<Switch id="smtp-starttls" bind:checked={smtpStartTLS} disabled={emailSettings?.managed_by_environment} />
					</div>
					<div class="flex items-center justify-between gap-4">
						<div>
							<Label for="smtp-tls" class="cursor-pointer font-normal">Implicit TLS</Label>
							<p class="text-xs text-muted-foreground">For port 465 (SSL)</p>
						</div>
						<Switch id="smtp-tls" bind:checked={smtpTLS} disabled={emailSettings?.managed_by_environment} />
					</div>
				</div>
			</div>

			<div class="mt-5 flex flex-wrap items-center gap-3">
				<Button onclick={save} disabled={savingFlag.active || emailSettings?.managed_by_environment}>
					{savingFlag.active ? 'Saving…' : 'Save'}
				</Button>
				<Button variant="outline" onclick={test} disabled={testingFlag.active || !emailSettings?.enabled}>
					{testingFlag.active ? 'Sending…' : 'Send test email'}
				</Button>
			</div>
			{#if emailSettings?.verified_at}
				<p class="mt-3 text-xs text-muted-foreground">Live test accepted {new Date(emailSettings.verified_at).toLocaleString()}.</p>
			{/if}
			{#if emailSettings?.last_delivery_status}
				<p class="mt-1 text-xs text-muted-foreground">Latest queued delivery: {emailSettings.last_delivery_status}.</p>
			{/if}
		</div>
	</div>
{/if}

{/if}
