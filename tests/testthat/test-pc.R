library(testthat)

Sys.setenv(WT_USERNAME = "guest", WT_PASSWORD = "Apple123")
wt_auth(force = TRUE)

################################### Point count test suite

test_that("Downloading PC report", {
  lpb_pc <- wt_download_report(887, 'PC', 'main')
  expect_true(!is.null(lpb_pc))
})

test_that("Downloading ARU as PC report", {
  cypress_hills_as_pc <- wt_download_report(620, 'PC', 'main')
  expect_true(!is.null(cypress_hills_as_pc))
})

test_that("Attempting PC as ARU report", {
  expect_true(nrow(wt_download_report(887, 'ARU', 'main')) == 0)
})

test_that('Occupancy for PC', {
  pc_data <- wt_download_report(887, 'PC', 'main')
  pc_tidy <- wt_tidy_species(pc_data, remove = c("unknown"), zerofill = T)
  pc_occu <- wt_format_occupancy(pc_tidy, species = "all")
  expect_true(class(pc_occu)[1] == 'unmarkedFrameOccu')
})

test_that('Error for TMTT', {
  pc_data <- wt_download_report(887, 'PC', 'main')
  pc_tidy <- wt_tidy_species(pc_data, remove = c("unknown"), zerofill = T)
  expect_error(wt_replace_tmtt(pc_tidy, calc = 'round'))
})

