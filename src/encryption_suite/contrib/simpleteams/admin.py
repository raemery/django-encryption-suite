from django.contrib import admin

from .models import SimpleTeam, SimpleTeamMembership


class SimpleTeamMembershipInline(admin.TabularInline):
    model = SimpleTeamMembership


@admin.register(SimpleTeam)
class SimpleTeamAdmin(admin.ModelAdmin):
    inlines = [SimpleTeamMembershipInline]
    # Declared so other admins can name SimpleTeam in autocomplete_fields. Django
    # never builds a query from it: see get_search_results.
    search_fields = ["name"]

    def get_search_results(self, request, queryset, search_term):
        """Match a part of the name, ignoring case, by decrypting every name in memory.

        The blind index answers only whether two whole names are equal, so the
        admin's ``icontains`` cannot run against the column. Teams are few
        enough to read in full on every search.
        """
        term = search_term.strip().casefold()
        if not term:
            return queryset, False
        matched = [team.pk for team in queryset if term in str(team.name).casefold()]
        return queryset.filter(pk__in=matched), False
